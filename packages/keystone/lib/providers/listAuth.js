const { mergeWhereClause } = require('@keystonejs/utils');
const { logger } = require('@keystonejs/logger');
const { AccessDeniedError } = require('../List/graphqlErrors');
const graphqlLogger = logger('graphql');

const upcase = str => str.substr(0, 1).toUpperCase() + str.substr(1);

const opToType = {
  read: 'query',
  create: 'mutation',
  update: 'mutation',
  delete: 'mutation',
};

class ListAuthProvider {
  constructor({ authStrategy, list }) {
    this.authStrategy = authStrategy;
    this.list = list;
    const { itemQueryName, outputTypeName } = list.gqlNames;
    this.gqlNames = {
      outputTypeName,
      authenticateOutputName: `authenticate${itemQueryName}Output`,
      unauthenticateOutputName: `unauthenticate${itemQueryName}Output`,
      authenticatedQueryName: `authenticated${itemQueryName}`,
      authenticateMutationName: `authenticate${itemQueryName}With${upcase(authStrategy.authType)}`,
      unauthenticateMutationName: `unauthenticate${itemQueryName}`,
    };
  }

  getTypes({}) {
    const { unauthenticateOutputName, authenticateOutputName, outputTypeName } = this.gqlNames;
    return [
      `
    type ${unauthenticateOutputName} {
      """
      \`true\` when unauthentication succeeds.
      NOTE: unauthentication always succeeds when the request has an invalid or missing authentication token.
      """
      success: Boolean
    }
  `,
      `
    type ${authenticateOutputName} {
      """ Used to make subsequent authenticated requests by setting this token in a header: 'Authorization: Bearer <token>'. """
      token: String
      """ Retrieve information on the newly authenticated ${outputTypeName} here. """
      item: ${outputTypeName}
    }
  `,
    ];
  }
  getQueries({}) {
    const { authenticatedQueryName, outputTypeName } = this.gqlNames;
    return [`${authenticatedQueryName}: ${outputTypeName}`];
  }
  getMutations({}) {
    const {
      authenticateMutationName,
      authenticateOutputName,
      unauthenticateMutationName,
      unauthenticateOutputName,
      outputTypeName,
    } = this.gqlNames;
    const { authStrategy } = this;
    const authTypeTitleCase = upcase(authStrategy.authType);
    return [
      `""" Authenticate and generate a token for a ${outputTypeName} with the ${authTypeTitleCase} Authentication Strategy. """
      ${authenticateMutationName}(${authStrategy.getInputFragment()}): ${authenticateOutputName}`,
      `${unauthenticateMutationName}: ${unauthenticateOutputName}`,
    ];
  }

  getTypeResolvers({}) {
    return {};
  }
  getQueryResolvers({}) {
    const { authenticatedQueryName } = this.gqlNames;
    return {
      [authenticatedQueryName]: (_, __, context, info) => this._authenticatedQuery(context, info),
    };
  }
  getMutationResolvers({}) {
    const { authenticateMutationName, unauthenticateMutationName } = this.gqlNames;
    const { authType } = this.authStrategy;
    return {
      [authenticateMutationName]: (_, args, context) =>
        this._authenticateMutation(authType, args, context),
      [unauthenticateMutationName]: (_, __, context) => this._unauthenticateMutation(context),
    };
  }

  _authenticatedQuery(context, info) {
    if (info && info.cacheControl) {
      info.cacheControl.setCacheHint({ scope: 'PRIVATE' });
    }

    if (!context.authedItem || context.authedListKey !== this.list.key) {
      return null;
    }

    const gqlName = this.gqlNames.authenticatedQueryName;
    const access = this.checkListAccess(context, { gqlName });
    return this.list.itemQuery(
      mergeWhereClause({ where: { id: context.authedItem.id } }, access),
      context,
      this.gqlNames.authenticatedQueryName
    );
  }

  async _authenticateMutation(authType, args, context) {
    const gqlName = this.gqlNames.authenticateMutationName;
    this.checkListAccess(context, { gqlName });

    // This is currently hard coded to enable authenticating with the admin UI.
    // In the near future we will set up the admin-ui application and api to be
    // non-public.
    const audiences = ['admin'];

    // Verify incoming details
    const { item, success, message } = await this.authStrategy.validate(args);
    if (!success) {
      throw new Error(message);
    }

    const token = await context.startAuthedSession({ item, list: this.list }, audiences);
    return { token, item };
  }

  async _unauthenticateMutation(context) {
    const gqlName = this.gqlNames.unauthenticateMutationName;
    this.checkListAccess(context, { gqlName });

    await context.endAuthedSession();
    return { success: true };
  }

  checkListAccess(context, { gqlName }) {
    const operation = 'auth';
    const access = context.getListAccessControlForUser(this.list.key, undefined, operation, {
      gqlName,
    });
    if (!access) {
      graphqlLogger.debug({ operation, access, gqlName }, 'Access statically or implicitly denied');
      graphqlLogger.info({ operation, gqlName }, 'Access Denied');
      // If the client handles errors correctly, it should be able to
      // receive partial data (for the fields the user has access to),
      // and then an `errors` array of AccessDeniedError's
      this._throwAccessDenied(operation, context, gqlName);
    }
    return access;
  }

  _throwAccessDenied(operation, context, target) {
    throw new AccessDeniedError({
      data: { type: opToType[operation], target },
      internalData: {
        authedId: context.authedItem && context.authedItem.id,
        authedListKey: context.authedListKey,
      },
    });
  }
}

module.exports = { ListAuthProvider };

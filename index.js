const fineacl = require('fineacl');

module.exports = ({koa, authorize}) => {

  /**
   * Koa authorize middleware
   */
  koa.app.use(async (ctx, next) => {
    
    /**
     * Describe permission requirements
     *
     * @param {String} resourceType
     * @param {String} resourceId
     * @param {Array|String} permissions
     */
    ctx.checkAccess = (resourceType, resourceId, permissions) => {
      permissions = Array.isArray(permissions) ? permissions : [permissions];
      ctx.__authzRequestedPermissions = ctx.__authzRequestedPermissions || [];
      ctx.__authzRequestedPermissions.push({resourceType, resourceId, permissions});
      return ctx;
    };

    /**
     * Enforce permissions
     */
    ctx.authorize = async () => {
      if (ctx.user && ctx.user.id) {
        const userPermissions = await authorize.user(ctx.user.id).getPermissions();
        const acl = fineacl();

        // compile existing relationships
        const existing = userPermissions.map(el => new Promise((resolve, reject) =>
          acl.rel({
            userId: el.userId,
            resourceType: el.resourceType,
            resourceId: el.resourceId,
            permissions: el.permissions
          })
          .sync((err, success) => {
            if (err) {
              reject(err);
            } else if (!success) {
              reject(new Error("Failed to enforce relationship"));
            } else {
              resolve();
            }
          })));
        await Promise.all(existing);

        // check if all requested permissions are granted
        const requested = ctx.__authzRequestedPermissions.map(el => new Promise((resolve, reject) =>
          acl.rel({
              userId: ctx.user.id,
              resourceType: el.resourceType,
              resourceId: el.resourceId,
              permissions: el.permissions
          })
          .assert((err, exists) => {
            if (err) {
              reject(err);
            } else if (!exists) {
              resolve(false);
            } else {
              resolve(true);
            }
          })));
        const result = await Promise.all(requested);
        if (result.filter(el => el === false).length === 0) {
          return true;
        } else {
          ctx.throw(403, new Error("access denied"));
        }
      } else {
        ctx.throw(401, new Error("authentication required"));
      }
    };

    ctx.authz = ctx.authorize;

    await next();
  });

  return {};
};
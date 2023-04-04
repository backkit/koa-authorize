const autoconf = require("@backkit/autoconf");

autoconf('koa-authorize')
.generator(self => ([
  {
    putFileOnce: self.serviceConfigMainYML,
    contentYml: self.config
  },
  {
    putFileOnce: self.serviceCodeMainJS,
    content: `module.exports = require('${self.npmModuleName}');`
  },
  {
    putFileOnce: `${self.serviceResourceDir}/.gitkeep`
  }
]))
.default(self => ({}))
.prompt(self => ([]))
.run()

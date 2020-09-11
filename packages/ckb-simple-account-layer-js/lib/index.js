const { CkbSimpleAccount: NativeCkbSimpleAccount } = require("../native");

class CkbSimpleAccount {
  constructor(config) {
    this.config = config;
    this.nativeCkbSimpleAccount = new NativeCkbSimpleAccount(config);
  }
  generate(program) {
    return this.nativeCkbSimpleAccount.generate(program);
  }
}

module.exports = { CkbSimpleAccount };

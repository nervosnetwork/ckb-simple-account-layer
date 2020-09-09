var { CkbSimpleAccount: NativeCkbSimpleAccount } = require("../native");

class CkbSimpleAccount {
  constructor(config) {
    this.config = config;
    this.nativeCkbSimpleAccount = new NativeCkbSimpleAccount(config);
  }
}

module.exports = { CkbSimpleAccount };

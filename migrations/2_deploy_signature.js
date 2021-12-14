const SignatureDemo = artifacts.require("SignatureDemo");

module.exports = function (deployer) {
  deployer.deploy(SignatureDemo);
};

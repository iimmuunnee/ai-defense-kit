const { ethers } = require("ethers");

const wallet = new ethers.Wallet(process.env.OPS_KEY, provider);
module.exports = { wallet };

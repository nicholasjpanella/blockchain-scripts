import hdkey from "hdkey";
import bs58 from "bs58";

import args from "../utils/parseArgs.js";
import {
  entropyToMnemonic,
  generateMnemonic,
  mnemonicToEntropy,
  mnemonicToSeedSync,
} from "bip39";

/**
 * |  MS  |  ENT  | CS | ENT+CS |
 * +------+-------+----+--------+
 * |  12  |  128  |  4 |   132  |
 * |  15  |  160  |  5 |   165  |
 * |  18  |  192  |  6 |   198  |
 * |  21  |  224  |  7 |   231  |
 * |  24  |  256  |  8 |   264  |
 */
export const strengthMap = {
  basic: [12, 128],
  enhanced: [15, 160],
  advanced: [18, 192],
  robust: [21, 224],
  fortified: [24, 256],
};

/**
 * validates a provided mnemonic, or generates one
 * @param {string} mnemonic
 * @param {string} strength
 * @returns {string} mnemonic
 */
export function withMnemonic(mnemonic, strength = "basic") {
  if (typeof mnemonic === "string" && mnemonic.length > 0) {
    const mnemonicSplit = String(mnemonic).split(/\s+|\n+/);
    const mnemonicLength = mnemonicSplit.length;
    const detectedLevel = Object.entries(strengthMap).find(
      ([, l]) => l.at(0) === mnemonicLength
    );
    if (!detectedLevel) console.warn("Warning: mnemonic size is abnormal");

    return mnemonicSplit.join(" ");
  }

  if (!Object.keys(strengthMap).includes(strength))
    throw Error("Not a known strength level");

  const [, ent] = strengthMap[strength];
  return generateMnemonic(ent);
}

/**
 * converts entropy to mnemonic
 * @param {string} entropy
 * @returns {string} mnemonic
 */
export function withEntropy(entropy) {
  return entropyToMnemonic(entropy);
}

/**
 * Constructs object full of key information for wallet generation
 * @param {object} config
 * @returns {object} of keys
 */
export function constructKeys({
  fromEntropy,
  fromMnemonic,
  fromPk,
  fromMasterSeed,
  strengthLevel = "basic",
  passphrase,
}) {
  const isImport = [fromPk, fromEntropy, fromMasterSeed, fromMnemonic].some(
    Boolean
  );
  const source = isImport ? "import" : "generated";

  if (typeof fromPk === "string" && fromPk.length > 0) {
    const root = hdkey.fromExtendedKey(fromPk);
    return {
      source,
      publicKey: root.publicKey.toString("hex"),
      extendedPublicKey: root.publicExtendedKey,
      privateKey: root.privateKey.toString("hex"),
      extendedPrivateKey: root.privateExtendedKey,
    };
  }

  if (typeof fromMasterSeed === "string" && fromMasterSeed.length > 0) {
    const root = hdkey.fromMasterSeed(bs58.decode(fromMasterSeed));
    return {
      source,
      publicKey: root.publicKey.toString("hex"),
      extendedPublicKey: root.publicExtendedKey,
      privateKey: root.privateKey.toString("hex"),
      extendedPrivateKey: root.privateExtendedKey,
    };
  }

  const mnemonic =
    typeof fromEntropy === "string"
      ? withEntropy(fromEntropy)
      : withMnemonic(fromMnemonic, strengthLevel);

  const seed = mnemonicToSeedSync(mnemonic, passphrase);
  const root = hdkey.fromMasterSeed(seed);

  return {
    mnemonic,
    source,
    entropy: mnemonicToEntropy(mnemonic),
    masterSeed: bs58.encode(seed),
    publicKey: root.publicKey.toString("hex"),
    extendedPublicKey: root.publicExtendedKey,
    privateKey: root.privateKey.toString("hex"),
    extendedPrivateKey: root.privateExtendedKey,
  };
}

if (args.print) {
  console.log(
    constructKeys({
      fromMnemonic: args.m ?? args.mnemonic,
    })
  );
}

/*
 * Copyright (c) 2022 James Hunt.  All Rights Reserved.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

const clone = o => Object.assign({}, o);

const isPacked = x => !(x instanceof Uint8Array);

const unpackByteArray = s => new Uint8Array(s.match(/.{1,2}/g).map(b => parseInt(b, 16)));
const packByteArray   = a => [...new Uint8Array(a)].reduce((s,b) => s + b.toString(16).padStart(2, '0'), '');

const unpackString = s => new Uint8Array(s.split('').map(c => c.charCodeAt(0)));
const packString   = a => String.fromCharCode(...new Uint8Array(a));


class PublicKeyCredentialCreationOptions {
  constructor(input) {
    this.packed   = {};
    this.unpacked = {};

    if (!input) {
      return
    }

    ['rp', 'user', 'pubKeyCredParams', 'authenticatorSelection', 'attestation', 'extensions']
      .map(f => {
        if (f in input) {
          this.packed[f]   = clone(input[f]);
          this.unpacked[f] = clone(input[f]);
        }
      });

    ['challenge', 'timeout']
      .map(f => {
        if (f in input) {
          this.packed[f]   = input[f];
          this.unpacked[f] = input[f];
        }
      });

    // user.id is a Buffer Source; we need to pack it
    if (input.user && input.user.id) {
      if (isPacked(input.user.id)) {
        this.unpacked.user.id = unpackByteArray(input.user.id);
      } else {
        this.packed.user.id = packByteArray(input.user.id);
      }
    }

    // challenge is a BufferSource; we need to pack it
    if ('challenge' in input) {
      if (isPacked(input.challenge)) {
        this.unpacked.challenge = unpackByteArray(input.challenge);
      } else {
        this.packed.challenge = packByteArray(input.challenge);
      }
    }

    // each id of excludeCredentials[] is a BufferSource
    if ('excludeCredentials' in input) {
      this.packed.excludeCredentials   = [];
      this.unpacked.excludeCredentials = [];

      input.excludeCredentials.forEach(ex => {
        const packed   = clone(ex);
        const unpacked = clone(ex);

        if (ex.id) {
          if (isPacked(ex.id)) {
            unpacked.id = unpackByteArray(ex.id);
          } else {
            packed.id = packByteArray(ex.id);
          }
        }
        this.packed.excludeCredentials.push(packed);
        this.unpacked.excludeCredentials.push(unpacked);
      });
    }
  }
}

class AuthenticatorAttestationResponse {
  constructor(input) {
    this.packed   = {};
    this.unpacked = {};

    if (!input) {
      return;
    }

    if ('attestationObject' in input) {
      const v = input.attestationObject;
      if (isPacked(v)) {
        this.unpacked.attestationObject = unpackByteArray(v);
        this.packed.attestationObject   = v;
      } else {
        this.unpacked.attestationObject = v;
        this.packed.attestationObject   = packByteArray(v);
      }
    }

    if ('clientDataJSON' in input) {
      const v = input.clientDataJSON;
      if (isPacked(v)) {
        this.unpacked.clientDataJSON = unpackString(v);
        this.packed.clientDataJSON   = v;
      } else {
        this.unpacked.clientDataJSON = v;
        this.packed.clientDataJSON   = packString(v);
      }

      this.clientData = JSON.parse(this.packed.clientDataJSON);
    }
  }
}

class PublicKeyCredentialRequestOptions {
  constructor(input) {
    this.packed   = {};
    this.unpacked = {};

    if (!input) {
      return;
    }

    ['extensions']
      .map(f => {
        if (f in input) {
          this.packed[f]   = clone(input[f]);
          this.unpacked[f] = clone(input[f]);
        }
      });

    ['challenge', 'timeout', 'rpId', 'userVerification']
      .map(f => {
        if (f in input) {
          this.packed[f]   = input[f];
          this.unpacked[f] = input[f];
        }
      })

    // challenge is a BufferSource; we need to pack it
    if ('challenge' in input) {
      if (isPacked(input.challenge)) {
        this.unpacked.challenge = unpackByteArray(input.challenge);
      } else {
        this.packed.challenge = packByteArray(input.challenge);
      }
    }

    // each id of allowCredentials[] is a BufferSource
    if ('allowCredentials' in input) {
      this.packed.allowCredentials   = [];
      this.unpacked.allowCredentials = [];

      input.allowCredentials.forEach(ex => {
        const packed   = clone(ex);
        const unpacked = clone(ex);

        if (ex.id) {
          if (isPacked(ex.id)) {
            unpacked.id = unpackByteArray(ex.id);
          } else {
            packed.id = packByteArray(ex.id);
          }
        }
        this.packed.allowCredentials.push(packed);
        this.unpacked.allowCredentials.push(unpacked);
      })
    }
  }
}

class AuthenticatorAssertionResponse {
  constructor(input) {
    this.packed   = {};
    this.unpacked = {};

    if (!input) {
      return
    }

    ['authenticatorData', 'signature', 'userHandle']
      .map(f => {
        if (f in input) {
          this.packed[f]   = input[f];
          this.unpacked[f] = input[f];

          if (isPacked(input[f])) {
            this.unpacked[f] = unpackByteArray(input[f]);
          } else {
            this.packed[f] = packByteArray(input[f]);
          }
        }
      });
  }
}

module.exports = {
  PublicKeyCredentialCreationOptions,
  AuthenticatorAttestationResponse,

  PublicKeyCredentialRequestOptions,
  AuthenticatorAssertionResponse,
}

/*
 * Copyright (c) 2022 James Hunt.  All Rights Reserved.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

const {
  PublicKeyCredentialCreationOptions,
  AuthenticatorAttestationResponse,

  PublicKeyCredentialRequestOptions,
  AuthenticatorAssertionResponse,
} = require('./objects.js')

test("PublicKeyCredentialCreationOptions handles empty objects", () => {
  const the = new PublicKeyCredentialCreationOptions({})
  expect(the).toBeDefined()
  expect(the.packed).toBeDefined()
  expect(the.unpacked).toBeDefined()
});

test("PublicKeyCredentialCreationOptions handles null objects", () => {
  const the = new PublicKeyCredentialCreationOptions(null)
  expect(the).toBeDefined()
  expect(the.packed).toBeDefined()
  expect(the.unpacked).toBeDefined()
});

['rp', 'user', 'pubKeyCredParams', 'authenticatorSelection', 'attestation', 'extensions',
 'timeout']
  .map(f => test(`PublicKeyCredentialCreationOptions passes through the '${f}' field`, () => {
      const the = new PublicKeyCredentialCreationOptions({
        [f]: { foo: "bar" }
      })
      expect(the).toBeDefined()

      expect(the.packed).toBeDefined()
      expect(the.packed[f].foo).toBe("bar")

      expect(the.unpacked).toBeDefined()
      expect(the.unpacked[f].foo).toBe(the.packed[f].foo)
    }));

test('PublicKeyCredentialCreationOptions handles binary user.id, if present', () => {
  const the = new PublicKeyCredentialCreationOptions({
    user: { id: new Uint8Array([222, 202, 251, 173]) }
  })

  expect(the).toBeDefined()

  expect(the.packed).toBeDefined()
  expect(the.packed.user).toBeDefined()
  expect(the.packed.user.id).toBeDefined()
  expect(the.packed.user.id).toEqual("decafbad")

  expect(the.unpacked).toBeDefined()
  expect(the.unpacked.user).toBeDefined()
  expect(the.unpacked.user.id).toBeDefined()
  expect(the.unpacked.user.id).toEqual(new Uint8Array([222, 202, 251, 173]))
});

test('PublicKeyCredentialCreationOptions handles hex user.id, if present', () => {
  const the = new PublicKeyCredentialCreationOptions({
    user: { id: 'decafbad' }
  })

  expect(the).toBeDefined()

  expect(the.packed).toBeDefined()
  expect(the.packed.user).toBeDefined()
  expect(the.packed.user.id).toBeDefined()
  expect(the.packed.user.id).toEqual("decafbad")

  expect(the.unpacked).toBeDefined()
  expect(the.unpacked.user).toBeDefined()
  expect(the.unpacked.user.id).toBeDefined()
  expect(the.unpacked.user.id).toEqual(new Uint8Array([222, 202, 251, 173]))
});

test('PublicKeyCredentialCreationOptions handles binary challenge, if present', () => {
  const the = new PublicKeyCredentialCreationOptions({
    challenge: new Uint8Array([222, 202, 251, 173])
  })

  expect(the).toBeDefined()

  expect(the.packed).toBeDefined()
  expect(the.packed.challenge).toBeDefined()
  expect(the.packed.challenge).toEqual("decafbad")

  expect(the.unpacked).toBeDefined()
  expect(the.unpacked.challenge).toBeDefined()
  expect(the.unpacked.challenge).toEqual(new Uint8Array([222, 202, 251, 173]))
});

test('PublicKeyCredentialCreationOptions handles hex challenge, if present', () => {
  const the = new PublicKeyCredentialCreationOptions({
    challenge: 'decafbad'
  })

  expect(the).toBeDefined()

  expect(the.packed).toBeDefined()
  expect(the.packed.challenge).toBeDefined()
  expect(the.packed.challenge).toEqual("decafbad")

  expect(the.unpacked).toBeDefined()
  expect(the.unpacked.challenge).toBeDefined()
  expect(the.unpacked.challenge).toEqual(new Uint8Array([222, 202, 251, 173]))
});

test('PublicKeyCredentialCreationOptions handles all excludeCredentials specs', () => {
  const the = new PublicKeyCredentialCreationOptions({
    excludeCredentials: [
      {
        id:   'decafbad',
        name: 'decaf-bad'
      },
      {
        id:   new Uint8Array([171,173, 29, 234]),
        name: 'a-bad-idea'
      },
      {
        name: 'no-id',
      }
    ]
  })

  expect(the).toBeDefined()

  expect(the.packed).toBeDefined()
  expect(the.packed.excludeCredentials).toBeDefined()
  expect(the.packed.excludeCredentials.length).toBe(3)
  expect(the.packed.excludeCredentials[0]).toEqual({
    id: 'decafbad',
    name: 'decaf-bad'
  })
  expect(the.packed.excludeCredentials[1]).toEqual({
    id: 'abad1dea',
    name: 'a-bad-idea'
  })
  expect(the.packed.excludeCredentials[2]).toEqual({
    name: 'no-id'
  })

  expect(the.unpacked).toBeDefined()
  expect(the.unpacked.excludeCredentials).toBeDefined()
  expect(the.unpacked.excludeCredentials.length).toBe(3)
  expect(the.unpacked.excludeCredentials[0]).toEqual({
    id: new Uint8Array([222, 202, 251, 173]),
    name: 'decaf-bad'
  })
  expect(the.unpacked.excludeCredentials[1]).toEqual({
    id: new Uint8Array([171,173, 29, 234]),
    name: 'a-bad-idea'
  })
  expect(the.unpacked.excludeCredentials[2]).toEqual({
    name: 'no-id'
  })
});


test("AuthenticatorAttestationResponse handles empty objects", () => {
  const the = new AuthenticatorAttestationResponse({})
  expect(the).toBeDefined()
  expect(the.packed).toBeDefined()
  expect(the.unpacked).toBeDefined()
});

test("AuthenticatorAttestationResponse handles null objects", () => {
  const the = new AuthenticatorAttestationResponse(null)
  expect(the).toBeDefined()
  expect(the.packed).toBeDefined()
  expect(the.unpacked).toBeDefined()
});

test('AuthenticatorAttestationResponse handles binary attestationObject, if present', () => {
  const the = new AuthenticatorAttestationResponse({
    attestationObject: new Uint8Array([222, 202, 251, 173])
  })

  expect(the).toBeDefined()

  expect(the.packed).toBeDefined()
  expect(the.packed.attestationObject).toBeDefined()
  expect(the.packed.attestationObject).toEqual("decafbad")

  expect(the.unpacked).toBeDefined()
  expect(the.unpacked.attestationObject).toBeDefined()
  expect(the.unpacked.attestationObject).toEqual(new Uint8Array([222, 202, 251, 173]))
});

test('AuthenticatorAttestationResponse handles hex attestationObject, if present', () => {
  const the = new AuthenticatorAttestationResponse({
    attestationObject: 'decafbad'
  })

  expect(the).toBeDefined()

  expect(the.packed).toBeDefined()
  expect(the.packed.attestationObject).toBeDefined()
  expect(the.packed.attestationObject).toEqual("decafbad")

  expect(the.unpacked).toBeDefined()
  expect(the.unpacked.attestationObject).toBeDefined()
  expect(the.unpacked.attestationObject).toEqual(new Uint8Array([222, 202, 251, 173]))
});

test('AuthenticatorAttestationResponse handles binary clientDataJSON, if present', () => {
  const the = new AuthenticatorAttestationResponse({
    clientDataJSON: new Uint8Array([
      123,
        34,
          105, 100, 101, 97,
        34,
        58,
        34,
          98, 97, 100,
        34,
      125
    ])
  })

  expect(the).toBeDefined()

  expect(the.packed).toBeDefined()
  expect(the.packed.clientDataJSON).toBeDefined()
  expect(the.packed.clientDataJSON).toEqual('{"idea":"bad"}')

  expect(the.unpacked).toBeDefined()
  expect(the.unpacked.clientDataJSON).toBeDefined()
  expect(the.unpacked.clientDataJSON).toEqual(new Uint8Array([
    123,
      34,
        105, 100, 101, 97,
      34,
      58,
      34,
        98, 97, 100,
      34,
    125
  ]))
  expect(the.clientData).toEqual({
    idea: "bad"
  })
});

test('AuthenticatorAttestationResponse handles hex clientDataJSON, if present', () => {
  const the = new AuthenticatorAttestationResponse({
    clientDataJSON: '{"idea":"bad"}'
  })

  expect(the).toBeDefined()

  expect(the.packed).toBeDefined()
  expect(the.packed.clientDataJSON).toBeDefined()
  expect(the.packed.clientDataJSON).toEqual('{"idea":"bad"}')

  expect(the.unpacked).toBeDefined()
  expect(the.unpacked.clientDataJSON).toBeDefined()
  expect(the.unpacked.clientDataJSON).toEqual(new Uint8Array([
    123,
      34,
        105, 100, 101, 97,
      34,
      58,
      34,
        98, 97, 100,
      34,
    125
  ]))
  expect(the.clientData).toEqual({
    idea: "bad"
  })
});




test("PublicKeyCredentialRequestOptions handles empty objects", () => {
  const the = new PublicKeyCredentialRequestOptions({})
  expect(the).toBeDefined()
  expect(the.packed).toBeDefined()
  expect(the.unpacked).toBeDefined()
});

test("PublicKeyCredentialRequestOptions handles null objects", () => {
  const the = new PublicKeyCredentialRequestOptions(null)
  expect(the).toBeDefined()
  expect(the.packed).toBeDefined()
  expect(the.unpacked).toBeDefined()
});

['extensions',
 'timeout', 'rpId', 'userVerification']
  .map(f => test(`PublicKeyCredentialRequestOptions passes through the '${f}' field`, () => {
      const the = new PublicKeyCredentialRequestOptions({
        [f]: { foo: "bar" }
      })
      expect(the).toBeDefined()

      expect(the.packed).toBeDefined()
      expect(the.packed[f].foo).toBe("bar")

      expect(the.unpacked).toBeDefined()
      expect(the.unpacked[f].foo).toBe(the.packed[f].foo)
    }));

test('PublicKeyCredentialRequestOptions handles binary challenge, if present', () => {
  const the = new PublicKeyCredentialRequestOptions({
    challenge: new Uint8Array([222, 202, 251, 173])
  })

  expect(the).toBeDefined()

  expect(the.packed).toBeDefined()
  expect(the.packed.challenge).toBeDefined()
  expect(the.packed.challenge).toEqual("decafbad")

  expect(the.unpacked).toBeDefined()
  expect(the.unpacked.challenge).toBeDefined()
  expect(the.unpacked.challenge).toEqual(new Uint8Array([222, 202, 251, 173]))
});

test('PublicKeyCredentialRequestOptions handles hex challenge, if present', () => {
  const the = new PublicKeyCredentialRequestOptions({
    challenge: 'decafbad'
  })

  expect(the).toBeDefined()

  expect(the.packed).toBeDefined()
  expect(the.packed.challenge).toBeDefined()
  expect(the.packed.challenge).toEqual("decafbad")

  expect(the.unpacked).toBeDefined()
  expect(the.unpacked.challenge).toBeDefined()
  expect(the.unpacked.challenge).toEqual(new Uint8Array([222, 202, 251, 173]))
});

test('PublicKeyCredentialRequestOptions handles all allowCredentials specs', () => {
  const the = new PublicKeyCredentialRequestOptions({
    allowCredentials: [
      {
        id:   'decafbad',
        name: 'decaf-bad'
      },
      {
        id:   new Uint8Array([171,173, 29, 234]),
        name: 'a-bad-idea'
      },
      {
        name: 'no-id',
      }
    ]
  })

  expect(the).toBeDefined()

  expect(the.packed).toBeDefined()
  expect(the.packed.allowCredentials).toBeDefined()
  expect(the.packed.allowCredentials.length).toBe(3)
  expect(the.packed.allowCredentials[0]).toEqual({
    id: 'decafbad',
    name: 'decaf-bad'
  })
  expect(the.packed.allowCredentials[1]).toEqual({
    id: 'abad1dea',
    name: 'a-bad-idea'
  })
  expect(the.packed.allowCredentials[2]).toEqual({
    name: 'no-id'
  })

  expect(the.unpacked).toBeDefined()
  expect(the.unpacked.allowCredentials).toBeDefined()
  expect(the.unpacked.allowCredentials.length).toBe(3)
  expect(the.unpacked.allowCredentials[0]).toEqual({
    id: new Uint8Array([222, 202, 251, 173]),
    name: 'decaf-bad'
  })
  expect(the.unpacked.allowCredentials[1]).toEqual({
    id: new Uint8Array([171,173, 29, 234]),
    name: 'a-bad-idea'
  })
  expect(the.unpacked.allowCredentials[2]).toEqual({
    name: 'no-id'
  })
});


test("AuthenticatorAssertionResponse handles empty objects", () => {
  const the = new AuthenticatorAssertionResponse({})
  expect(the).toBeDefined()
  expect(the.packed).toBeDefined()
  expect(the.unpacked).toBeDefined()
});

test("AuthenticatorAssertionResponse handles null objects", () => {
  const the = new AuthenticatorAssertionResponse(null)
  expect(the).toBeDefined()
  expect(the.packed).toBeDefined()
  expect(the.unpacked).toBeDefined()
});

['authenticatorData', 'signature', 'userHandle']
  .map(f => test(`AuthenticatorAssertionResponse handles binary ${f}, if present`, () => {
    const the = new AuthenticatorAssertionResponse({
      [f]: new Uint8Array([222, 202, 251, 173])
    })

    expect(the).toBeDefined()

    expect(the.packed).toBeDefined()
    expect(the.packed[f]).toBeDefined()
    expect(the.packed[f]).toEqual("decafbad")

    expect(the.unpacked).toBeDefined()
    expect(the.unpacked[f]).toBeDefined()
    expect(the.unpacked[f]).toEqual(new Uint8Array([222, 202, 251, 173]))
  }));

['authenticatorData', 'signature', 'userHandle']
  .map(f => test(`AuthenticatorAssertionResponse handles hex ${f}, if present`, () => {
    const the = new AuthenticatorAssertionResponse({
      [f]: 'decafbad'
    })

    expect(the).toBeDefined()

    expect(the.packed).toBeDefined()
    expect(the.packed[f]).toBeDefined()
    expect(the.packed[f]).toEqual("decafbad")

    expect(the.unpacked).toBeDefined()
    expect(the.unpacked[f]).toBeDefined()
    expect(the.unpacked[f]).toEqual(new Uint8Array([222, 202, 251, 173]))
  }));

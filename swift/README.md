# Secure AI for Swift

Private AI chat and guarded agent actions for iPhone, iPad, Mac, Watch and
Vision Pro. Names, emails, phone numbers and cards are swapped for stand-ins
before a model reads them and put back in the answer.

No dependencies. iOS 15, macOS 12 and later.

## Install

In Xcode: **File → Add Package Dependencies…**, then paste

```
https://github.com/secureaione-jpg/secure-ai-sdk
```

and add the `SecureAI` library to your app.

## Ask a model, privately

```swift
import SecureAI

let sai = SecureAI(apiKey: "sai_...")

let reply = try await sai.chat("Draft a reply to Sara Whitfield on 07700 900123")
// The model saw a stand-in. `reply` has Sara's real name and number in it.
```

A whole conversation, written out as it arrives:

```swift
for try await piece in sai.stream([.system("Be brief."), .user(question)]) {
    answer += piece
}
```

No piece ever holds a stand-in: the real values are put back before each one
leaves Secure AI.

### With your own model key

```swift
let reply = try await sai.chat(
    [.user(question)],
    model: "claude-sonnet-5",
    using: .yourKey("sk-ant-...")
)
```

Your vendor's key goes to the one call that needs it and is never stored.

## Secure mode: nobody in between can read it

```swift
let answer = try await sai.secureChat([.user("Summarise Sara Whitfield's file")]) { piece in
    text += piece
}
```

The conversation is sealed on the device to a key that exists only inside an
AWS Nitro enclave, after checking AWS's signed proof of which program holds
it — with Apple's own certificate verifier, against the pinned AWS root.
Secure AI relays it without being able to open it. If the proof does not
check out, nothing is sent and `SecureModeError` is thrown with
`reason == .unverified`.

Part of the API subscription, priced per message. Pin the enclave builds you
trust with `SecureAI(apiKey:trustedImages:)`; otherwise the list
`GET /v1/sealed` publishes is used.

## Just hide and restore

When you call the model yourself:

```swift
let hidden = try await sai.redact("Email Sara Whitfield at sara@example.com")
let answer = try await myModel.complete(hidden.text)
let readable = try await sai.restore(answer, map: hidden.map)
```

Keep `hidden.map` for the conversation. It is the only way to turn an answer
back, and **it is not stored on our side**.

## Guard an action

`guard` wraps something your app's agent does. The wrapped closure is called
with the **rewritten** input, and is never called when your rules refuse it:

```swift
struct Mail: Codable, Sendable { let to: String; let body: String }

let send = sai.guard("email.send") { (mail: Mail) in
    try await mailer.send(mail)
}

try await send(Mail(to: "ana@clientfirm.com", body: "About invoice 4471…"))
```

A refusal throws `ActionBlocked`. An action your rules hold for a person
waits for them and throws `ApprovalRefused` if they say no.

## Your key in an app

Anything compiled into an app can be read out of it. Either:

- keep the key on your server and point `baseURL` at a route there that adds
  it, or
- give the key your app carries a **monthly spending limit** in Settings →
  Developer, so a key lifted from the app cannot spend more than that.

```swift
let sai = SecureAI(apiKey: "sai_...", baseURL: URL(string: "https://api.yourapp.com/secure-ai")!)
```

## Errors

`SecureAIError` carries the HTTP `status` and a `code`:

| code | means |
|---|---|
| `free_limit` | The free 1,000 requests this month are used |
| `insufficient_balance` | Out of balance; top up in the app |
| `invalid_api_key` | No key, or not one we know |

Full reference: <https://secureai.one/developers>

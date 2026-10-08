# Secure AI for Kotlin

Private AI chat and guarded agent actions for Android and the JVM. Names,
emails, phone numbers and cards are swapped for stand-ins before a model reads
them and put back in the answer.

One dependency, `kotlinx-coroutines`, which an Android app already has.
Android 7 (API 24) and Java 17 and later.

## Install

From [JitPack](https://jitpack.io/#secureaione-jpg/secure-ai-sdk). In
`settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://jitpack.io")
    }
}
```

and in your app's `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.github.secureaione-jpg:secure-ai-sdk:0.1.0")
}
```

Calls the network, so your app needs `android.permission.INTERNET`.

## Ask a model, privately

```kotlin
import one.secureai.SecureAI

val sai = SecureAI(apiKey = "sai_...")

viewModelScope.launch {
    val reply = sai.chat("Draft a reply to Sara Whitfield on 07700 900123")
    // The model saw a stand-in. `reply` has Sara's real name and number in it.
}
```

Every call is a `suspend` function and runs off the main thread.

A whole conversation, written out as it arrives:

```kotlin
sai.stream(listOf(ChatMessage.system("Be brief."), ChatMessage.user(question)))
    .collect { piece -> answer += piece }
```

No piece ever holds a stand-in: the real values are put back before each one
leaves Secure AI.

### With your own model key

```kotlin
val reply = sai.chat(
    listOf(ChatMessage.user(question)),
    model = "claude-sonnet-5",
    using = ModelAccess.YourKey("sk-ant-..."),
)
```

Your vendor's key goes to the one call that needs it and is never stored.

## Just hide and restore

When you call the model yourself:

```kotlin
val hidden = sai.redact("Email Sara Whitfield at sara@example.com")
val answer = myModel.complete(hidden.text)
val readable = sai.restore(answer, hidden.map)
```

Keep `hidden.map` for the conversation. It is the only way to turn an answer
back, and **it is not stored on our side**.

## Guard an action

`guard` wraps something your app's agent does. The wrapped function is called
with the **rewritten** input, and is never called when your rules refuse it:

```kotlin
val send = sai.guard("email.send") { mail -> mailer.send(mail) }

send(mapOf("to" to "ana@clientfirm.com", "body" to "About invoice 4471…"))
```

A refusal throws `ActionBlocked`. An action your rules hold for a person
waits for them and throws `ApprovalRefused` if they say no.

## Your key in an app

Anything in an APK can be read out of it. Either:

- keep the key on your server and point `baseUrl` at a route there that adds
  it, or
- give the key your app carries a **monthly spending limit** in Settings →
  Developer, so a key lifted from the app cannot spend more than that.

```kotlin
val sai = SecureAI(apiKey = "sai_...", baseUrl = "https://api.yourapp.com/secure-ai")
```

## Errors

`SecureAIException` carries the HTTP `status` and a `code`:

| code | means |
|---|---|
| `free_limit` | The free 1,000 requests this month are used |
| `insufficient_balance` | Out of balance; top up in the app |
| `invalid_api_key` | No key, or not one we know |

Full reference: <https://secureai.one/developers>

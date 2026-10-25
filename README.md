# AdShield

A tiny personal ad blocker for Android. It is a local DNS sinkhole: names on the built-in list get a dead-end
answer, everything else is forwarded to the resolver you pick (Cloudflare, Google or Quad9).

## What it does and does not do

- **No third-party code.** No libraries, no analytics, no crash reporting, no ads, no list downloads.
- **One permission:** `INTERNET`, used only to forward non-blocked DNS lookups to your chosen resolver.
- **Your traffic is not routed through the app.** The VPN claims a single `/32` route for a fake DNS address
  (`10.111.222.2`), so only DNS questions reach AdShield. Pages, videos and apps connect directly.
- **Nothing is stored** except your resolver choice and allow-list (private app storage). Counters and the
  "recently blocked" list live in memory only. Backups are disabled.
- The block list is [StevenBlack/hosts](https://github.com/StevenBlack/hosts) (MIT), ~71k domains, baked into the APK.

Limits of DNS blocking: it cannot remove ads served from the same domain as the content (YouTube video ads,
Instagram/Facebook feed ads, many in-app ads). Apps or browsers using their own encrypted DNS (e.g. Firefox DoH)
bypass it, as does Android's strict "Private DNS" setting (the app warns you). DNS-over-TCP lookups (rare, only
used for very large answers) are not handled.

## Build

Push to GitHub, open **Actions -> build-apk -> Run workflow**, then download the `AdShield-apk` artifact
(a zip containing `app-release.apk`). Tick *refresh_list* to bake in the newest list.
Every run also executes the self-test in `tools/DnsSelfTest.java`.

To build locally instead: open the folder in Android Studio (or run `gradle assembleRelease` with Gradle 8.9+ and
JDK 17 + Android SDK 34).

## Install and use

1. Install the APK (allow "install unknown apps" for your file manager/browser once).
2. Open AdShield -> **Turn on** -> accept Android's VPN prompt.
3. Optional but recommended: Settings -> Network -> VPN -> AdShield gear -> **Always-on VPN**. Android then
   restarts it after reboots. Leave "Block connections without VPN" off.
4. If a site breaks, add its domain to **Allow list**.

## Signing key

This repository is public, so no key is stored in it. Each GitHub build generates a fresh one-off key, which means
**you must uninstall the previous AdShield before installing a new build** (your only settings are the resolver and
the allow-list). For a stable key so updates install in place, create a keystore yourself and add two repository
secrets: `KEYSTORE_B64` (the .jks file, base64-encoded; alias `adshield`) and `KEYSTORE_PASS` (store and key password).
Local Android Studio builds fall back to the standard debug key.

## Refreshing the block list

`python3 tools/update_blocklist.py` rewrites `app/src/main/assets/blocklist.txt` (strictly validates every entry).

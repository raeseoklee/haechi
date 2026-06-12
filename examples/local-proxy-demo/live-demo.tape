# VHS tape for the Haechi LIVE demo (real upstream model).
# Regenerate the README GIF with:
#   HAECHI_LIVE_UPSTREAM is set below via Env so it stays out of the recording.
#   vhs examples/local-proxy-demo/live-demo.tape    (run from the repo root)

Output docs/assets/haechi-demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1180
Set Height 840
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms

# Point these at a reachable OpenAI-compatible server before recording. Using Env
# (not the typed command) keeps the upstream URL out of the captured GIF.
Env HAECHI_LIVE_UPSTREAM "http://127.0.0.1:8000"
Env HAECHI_LIVE_MODEL "Qwen/Qwen3.6-35B-A3B-FP8"

Sleep 500ms
Type "node examples/local-proxy-demo/live-demo.mjs"
Sleep 600ms
Enter
Sleep 9s

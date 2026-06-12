# VHS tape for the Haechi local end-to-end demo.
# Regenerate the README GIF with:  vhs examples/local-proxy-demo/demo.tape
# (run from the repo root; requires vhs + ttyd + ffmpeg)

Output docs/assets/haechi-demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1180
Set Height 840
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms

Sleep 500ms
Type "node examples/local-proxy-demo/demo.mjs"
Sleep 600ms
Enter
Sleep 9s

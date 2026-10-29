# Record the demo GIF with VHS (https://github.com/charmbracelet/vhs):
#   go build -o /tmp/tattlr ./cmd/tattlr
#   vhs scripts/demo.tape
# Writes docs/demo.gif. Nothing in it touches your real HOME.

Output docs/demo.gif

Require go
Require bash

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 820
Set Padding 18
Set TypingSpeed 35ms
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful

Hide
Type "unset NO_COLOR FORCE_COLOR; export TERM=xterm-256color TATTLR=/tmp/tattlr DEMO_PACE=1.2 PS1='$ '"
Enter
Type "clear"
Enter
Show

Type "scripts/demo.sh"
Sleep 500ms
Enter
Sleep 45s

# rxray demo tape — regenerate with:  vhs assets/demo.tape
# Requires the `rxray` binary on PATH (cargo install --path .) and vhs.

Output assets/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1280
Set Height 760
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type "clear" Enter
Show

Sleep 600ms
Type "# rxray: deterministic regex ReDoS complexity analysis (no LLM, no execution)"
Enter
Sleep 1200ms

Type "rxray 'a+b+'                  # safe pattern"
Sleep 500ms
Enter
Sleep 1800ms

Type "rxray 'a*a*$'                 # quadratic backtracking"
Sleep 500ms
Enter
Sleep 1800ms

Type "rxray --attack '(a+)+$'       # exponential + a verified attack string"
Sleep 500ms
Enter
Sleep 2200ms

Type "# Exit codes make it a CI gate: 0 = ok, 1 = vulnerable, 2 = error"
Enter
Sleep 1000ms
Type "rxray '(a+)+$'; echo exit=$?"
Sleep 500ms
Enter
Sleep 2500ms

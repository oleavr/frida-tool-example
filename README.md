### How to build and run

```sh
$ git clone git://github.com/oleavr/frida-tool-example.git
$ cd frida-tool-example/
$ npm install
$ node dist/bin/frida-tool-example.js -U -f com.example.android
```

### Development workflow

To continuously recompile on change, keep this running in a terminal:

```sh
$ npm run build-app:watch
```

Plus another terminal with:

```sh
$ npm run build-agent:watch
```

And use an editor like Visual Studio Code for code completion and instant
type-checking feedback.
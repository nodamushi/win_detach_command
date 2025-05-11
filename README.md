# Win Detach Command

Windows でDetachプロセスをコンソールあり・なしで起動することができる Command もどき。

```rs
let mut cmd = WinDetachCommand::new("your.exe");
cmd.arg("arg1")
   .set_env("ENV_VAR", "VALUE")
   .show_console(true); // Show console or not
let pid = cmd.spawn()?;
```

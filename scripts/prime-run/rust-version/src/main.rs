use std::{
    env,
    process::{Command, Stdio},
    os::unix::process::CommandExt,
};

fn main() {
    let mut args = env::args().skip(1).peekable();
    let mut detach = false;

    while let Some(arg) = args.peek() {
        match arg.as_str() {
            "-d" | "--detach" => {
                detach = true;
                args.next();
            }
            _ => break,
        }
    }

    let command_args: Vec<String> = args.collect();
    if command_args.is_empty() {
        eprintln!("Error: No command provided");
        std::process::exit(1);
    }

    let env_vars = [
        ("__NV_PRIME_RENDER_OFFLOAD", "1"),
        ("__GLX_VENDOR_LIBRARY_NAME", "nvidia"),
        ("__VK_LAYER_NV_optimus", "VK_LAYER_NV_optimus"),
    ];

    let mut cmd = Command::new(&command_args[0]);
    cmd.args(&command_args[1..]).envs(env_vars.into_iter());

    let result = if detach {
        // Split command configuration for unsafe block
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
            
        // Wrap the unsafe pre_exec call in an unsafe block
        unsafe {
            cmd.pre_exec(|| {
                unsafe { libc::setsid() };
                Ok(())
            });
        }

        cmd.spawn()
            .map(|_| ())
    } else {
        cmd.status()
            .map(|status| std::process::exit(status.code().unwrap_or(1)))
    };

    if let Err(e) = result {
        eprintln!("Failed to execute command: {}", e);
        std::process::exit(1);
    }
}

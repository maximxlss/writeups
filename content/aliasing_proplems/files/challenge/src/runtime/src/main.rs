use payload::payload;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, Result
};
use std::convert::TryInto;
use libc;

pub fn main() -> Result<()> {
    let security_key = SeccompRule::new(vec![
        SeccompCondition::new(
            5,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::Eq,
            0x1337133713371337,
        )?,
    ])?;

    let filter: BpfProgram = SeccompFilter::new(
        vec![
            (libc::SYS_open, vec![security_key.clone()]),
            (libc::SYS_sendfile, vec![security_key])
        ]
        .into_iter()
        .collect(),
        SeccompAction::KillProcess, // by default
        SeccompAction::Allow, // if key matches
        std::env::consts::ARCH.try_into()?,
    )?
    .try_into()?;

    seccompiler::apply_filter(&filter)?;
    
    payload();

    Ok(())
}


#[macro_export]

macro_rules! nom_debug_err {
    ($a:expr) => {{
        use anyhow::anyhow;
        $a.map_err(|err| anyhow!("error {:?} at: {:?}", err.code, err.input))
    }};
}

macro_rules! nom_remainder_err {
    ($a:expr) => {{
        use anyhow::ensure;
        let (next, res) = $a;
        ensure!(next.len() != 0, "Too manywere given");
        Ok(res)
    }};
}

pub(crate) use {nom_debug_err, nom_remainder_err};

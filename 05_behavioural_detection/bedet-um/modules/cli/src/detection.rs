pub(crate) fn start_detection(bedet_sig_path: String) -> anyhow::Result<()> {
    let signatures = signatures::deserialize_bedet_set_from_path(bedet_sig_path.as_str())?;
    detection::start_detection(signatures);
    Ok(())
}

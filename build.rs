fn main() {
    pyo3_build_config::use_pyo3_cfgs();
    println!("cargo:rustc-check-cfg=cfg(queue_native_buffer)");
    let config = pyo3_build_config::get();
    if !config.is_free_threaded()
        && (!config.abi3 || (config.version.major, config.version.minor) >= (3, 11))
    {
        println!("cargo:rustc-cfg=queue_native_buffer");
    }
}

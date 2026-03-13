fn main() {
    #[cfg(target_os = "windows")]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("PETriage_icon.ico");
        res.compile().expect("failed to compile Windows resources");
    }
}

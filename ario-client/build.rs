fn main() {
    #[cfg(feature = "graphql")]
    {
        cynic_codegen::register_schema("arweave")
            .from_sdl_file("graphql/arweave-schema.graphql")
            .unwrap()
            .as_default()
            .unwrap();
    }
}

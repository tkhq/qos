pub mod google {
    pub mod rpc {
        include!("google.rpc.rs");
    }
}
pub mod grpc {
    pub mod health {
        pub mod v1 {
            include!("grpc.health.v1.rs");
        }
    }
}
pub mod health {
    include!("health.rs");
}

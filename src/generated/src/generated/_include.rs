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
pub mod services {
    pub mod attestation {
        pub mod v1 {
            include!("services.attestation.v1.rs");
        }
    }
    pub mod health_check {
        pub mod v1 {
            include!("services.health_check.v1.rs");
        }
    }
    pub mod reshard {
        pub mod v1 {
            include!("services.reshard.v1.rs");
        }
    }
}

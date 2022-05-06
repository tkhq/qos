FROM rust:1.60 as builder

RUN USER=root cargo new --bin qos
WORKDIR ./qos
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
RUN cargo build --release
RUN rm src/*.rs

ADD . ./

RUN rm ./target/release/deps/qos*
RUN cargo build --release

FROM debian
ARG APP=/usr/src/app

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata procps netcat \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8000

ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /qos/target/release/qos ${APP}/qos

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

# CMD ["./enclave", "server", "--port", "5005"]
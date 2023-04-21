FROM rust:bullseye

WORKDIR /work

RUN DEBIAN_FRONTEND=noninteractive
RUN apt-get update 
Run apt-get install build-essential
ADD . .
RUN cargo build --release

CMD cargo run --release

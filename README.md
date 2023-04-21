# Metadata server 

Works as a load balancer for multiple cache servers.
Should be the entrypoint to server simulation data.

## Running

There is a `Dockerfile` which will create a image that can be used to run the
server.

To build the image:
```bash
$ docker build . -t metadata-server
```

To run the server using the host network.
```bash
$ docker run --network host metadata-server
```

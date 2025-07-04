## Setup nitro dev box

1. Launch latest Debian AMI
2. Connect to instance
    ```
    while sleep 1; do ssh admin@<IP_HERE>; done
    ```
3. Configure custom nitro kernel

    Assumes kernel "6.1" is latest. Adjust accordingly.
    ```
    sudo -s
    apt install -y tmux dpkg-dev pahole inotify-tools neovim build-essential linux-source-6.1.0
    cd /usr/src
    tar -xvf linux-source-6.1.tar.xz
    cd linux-source-6.1
    cp /boot/config-$(uname -r) .
    scripts/config --disable SYSTEM_TRUSTED_KEYS
    scripts/config --disable SYSTEM_REVOCATION_KEYS
    scripts/config --module NITRO_ENCLAVES
    make deb-pkg LOCALVERSION=-nitro KDEB_PKGVERSION=$(make kernelversion)-1
    dpkg -i ../linux-image-6.1.37-nitro_6.1.37-1_amd64.deb
    reboot
    ```
4. Setup latest docker
    ```
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
      "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt update
    sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    ```
5. Configure Nitro Enclave tooling
    ```
    git clone https://github.com/aws/aws-nitro-enclaves-cli.git
    cd aws-nitro-enclaves-cli
    make
    sudo mkdir -p /run/nitro_enclaves /etc/nitro_enclaves /var/log/nitro_enclaves
    sudo chmod -R g+w /var/log/nitro_enclaves /run/nitro_enclaves /etc/nitro_enclaves
    sudo chown -R :admin /var/log/nitro_enclaves /run/nitro_enclaves /etc/nitro_enclaves
    sudo cp build/nitro_cli/x86_64-unknown-linux-musl/release/nitro-cli /usr/local/bin/
    sudo cp bootstrapnitro-enclaves-allocator /usr/local/bin/
    sudo cp bootstrap/allocator.yaml /etc/
    sed -i 's|/usr/bin|/usr/local/bin|g' bootstrap/nitro-enclaves-allocator.service
    sudo cp bootstrap/nitro-enclaves-allocator.service /etc/systemd/system/
    sudo systemctl enable nitro-enclaves-allocator.service
    ```

## Terminate enclaves automatically when new EIF file is written

```
while inotifywait -e close_write out/aws-x86_64.eif; do sudo nitro-cli terminate-enclave --all; done
```

## Run debug enclave with nitro-cli in a loop:
```
while sleep 1; do sudo nitro-cli run-enclave --enclave-name nitro --memory 1024 --enclave-cid 16 --cpu-count 2 --eif-path out/aws-x86_64.eif --debug-mode --attach-console; done
```

## manually run qos_host:
```
./dist/qos_host.linux-x86_64 --host-ip 0.0.0.0 --host-port 3000 --cid 16 --port 3
```

## run health check in loop:
```
while sleep 1; do clear; date; curl localhost:3000/qos/enclave-health; done
```

## Vim command to save and trigger new enclave build/launch:
```
:w|! time make out/aws-x86_64.eif
```

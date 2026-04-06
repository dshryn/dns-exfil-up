**Install Zeek on WSL**

```wsl
sudo apt update
sudo apt install zeek -y
```

**Prepare Zeek logs dir**

```wsl
mkdir ~/zeek_output
cd ~/zeek_output
```

**Run Zeek and output logs to specific folder**

```wsl
zeek -C -r sample.pcap Log::default_logdir=./logs
```

**To process only DNS traffic**

```wsl
zeek -r sample.pcap dns
```

**Convert Zeek logs to JSON (optional, useful for ML)**

```wsl
zeek -r sample.pcap LogAscii::use_json=T
```

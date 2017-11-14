# Overview
LanQP enables tunnelling of packets over an AMQP router network.
The lanqp-proactor executable relies on the following command line
options:

| Option | Description |
| ------ | ----------- |
| -a <address> | The address of the AMQ Interconnect network connection in the form `host:port` |
| -d | Daemonize the process |
| -P <file> | The PID file for the daemonized process |
| -U <user> | The user for the daemon to run as |

The lanqp-proactor executable also relies on the following environment variables:

| Env Var | Description |
| ------- | ----------- |
| LANQP_IF_COUNT | Number of tun interfaces |
| LANQP_IFn_NAME | The interface name where n >= 0 (default is `lanq0`) |

# Prerequisites
Install Fedora 27 Workstation.  Then install packages needed to
build and run qpid-proton and lanqp-proactor.

    sudo dnf -y update
    sudo dnf -y install \
        gcc gcc-c++ make cmake libuuid-devel openssl-devel \
        cyrus-sasl-devel cyrus-sasl-plain cyrus-sasl-md5 swig \
        python-devel ruby-devel rubygem-minitest php-devel \
        perl-devel epydoc doxygen valgrind graphviz \
        python3-tox tunctl qpid-dispatch-tools \
        qpid-dispatch-router
    sudo dnf -y clean all
    sudo systemctl reboot

# Build and Install
Build and install a newer version of qpid-proton since its needed
by lanqp-proactor.

    git clone https://github.com/apache/qpid-proton.git -b 0.18.1
    cd qpid-proton
    mkdir build
    cd build
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DSYSINSTALL_BINDINGS=ON
    make all docs
    sudo make install

Build the lanqp-proactor application to tunnel packets over AMQP.

    cd ../..
    git clone https://github.com/ajssmith/lanqp-proactor.git
    cd lanqp-proactor
    mkdir build
    cd build
    cmake ..
    make

# Test
Create two tunnel devices.  Feel free to use an alternative
unprivileged user instead of `rlucente`.

    sudo tunctl -t lanq0 -n -u rlucente
    sudo ifconfig lanq0 10.254.1.1 netmask 255.255.0.0 up

    sudo tunctl -t lanq1 -n -u rlucente
    sudo ifconfig lanq1 10.254.1.2 netmask 255.255.0.0 up

Start the qpid-dispatch router.

    sudo systemctl start qdrouterd

Configure and start lanqp-proactor which will bring up the tun
interfaces.

    export LANQP_IF_COUNT=2
    export LANQP_IF0_NAME=lanq0
    export LANQP_IF1_NAME=lanq1
    ./lanqp-proactor -a localhost:amqp -d

# Cleanup
To shut it all down and remove the tunnel devices:

    pkill lanqp
    sudo systemctl stop qdrouterd
    sudo ip tuntap del mode tun name lanq0
    sudo ip tuntap del mode tun name lanq1


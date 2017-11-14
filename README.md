# Base Install
Install Fedora 27 Workstation.  After install,

    sudo dnf -y update
    sudo dnf -y clean all
    sudo systemctl reboot

# Build and Install
After reboot, install packages needed to build qpid-proton and lanqp-proactor.

    sudo dnf -y install \
        gcc gcc-c++ make cmake libuuid-devel openssl-devel \
        cyrus-sasl-devel cyrus-sasl-plain cyrus-sasl-md5 swig \
        python-devel ruby-devel rubygem-minitest php-devel \
        perl-devel epydoc doxygen valgrind graphviz \
        python3-tox tunctl

Install packages needed to run the dispatch router.

    sudo dnf -y install qpid-dispatch-tools qpid-dispatch-router

Build and install a newer version of qpid-proton.

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

# Test the lanqp-proactor capability
Create two tunnel devices.

    sudo tunctl -t lanq0 -n -u rlucente
    sudo ifconfig lanq0 10.254.1.1 netmask 255.255.0.0 up

    sudo tunctl -t lanq1 -n -u rlucente
    sudo ifconfig lanq1 10.254.1.2 netmask 255.255.0.0 up

Start the qpid-dispatch router.

    sudo qdrouterd -d

Configure and start lanqp-proactor.

    export LANQP_IF_COUNT=2
    export LANQP_IF0_NAME=lanq0
    export LANQP_IF1_NAME=lanq1
    ./lanqp-proactor -a localhost:amqp -d


/// Gopher UDP listener

function ListenerUI(mode_create)
{
    let labelHost = form.create_label("Host & port (Bind):");
    let comboHostBind = form.create_combo();
    comboHostBind.setEnabled(mode_create)
    comboHostBind.clear();
    let addrs = ax.interfaces();
    for (let item of addrs) { comboHostBind.addItem(item); }
    let spinPort = form.create_spin();
    spinPort.setRange(1, 65535);
    spinPort.setValue(9000);
    spinPort.setEnabled(mode_create)

    let labelCallback = form.create_label("Callback addresses:");
    let texteditCallback = form.create_textmulti();
    texteditCallback.setPlaceholder("192.168.1.1:9000\nserver2.com:9000");

    let labelTimeout = form.create_label("Timeout (sec):");
    let spinTimeout = form.create_spin();
    spinTimeout.setRange(1, 1000000);
    spinTimeout.setValue(10);

    let labelBanner = form.create_label("TCP banner:");
    let texteditBanner = form.create_textmulti("AdaptixC2 server\n");

    let labelAnswer = form.create_label("Error answer:");
    let texteditAnswer = form.create_textmulti("Connection error...\n");

    let labelEncryptKey = form.create_label("Encryption key:");
    let textlineEncryptKey = form.create_textline(ax.random_string(32, "hex"));
    textlineEncryptKey.setEnabled(mode_create)
    let buttonEncryptKey = form.create_button("Generate");
    buttonEncryptKey.setEnabled(mode_create)

    let checkMtls = form.create_check("Use mTLS");
    checkMtls.setEnabled(mode_create)

    let howButton = form.create_button("How generate?");

    let caCertSelector = form.create_selector_file();
    caCertSelector.setPlaceholder("CA cert");
    caCertSelector.setEnabled(false);

    let srvCertSelector = form.create_selector_file();
    srvCertSelector.setPlaceholder("Server cert");
    srvCertSelector.setEnabled(false);

    let srvKeySelector = form.create_selector_file();
    srvKeySelector.setPlaceholder("Server key");
    srvKeySelector.setEnabled(false);

    let clientCertSelector = form.create_selector_file();
    clientCertSelector.setPlaceholder("Client cert");
    clientCertSelector.setEnabled(false);

    let clientKeySelector = form.create_selector_file();
    clientKeySelector.setPlaceholder("Client key");
    clientKeySelector.setEnabled(false);

    let layout = form.create_gridlayout();
    layout.addWidget(labelHost,          0, 0, 1, 1);
    layout.addWidget(comboHostBind,      0, 1, 1, 2);
    layout.addWidget(spinPort,           0, 3, 1, 1);
    layout.addWidget(labelCallback,      1, 0, 1, 1);
    layout.addWidget(texteditCallback,   1, 1, 1, 3);
    layout.addWidget(labelTimeout,       2, 0, 1, 1);
    layout.addWidget(spinTimeout,        2, 1, 1, 3);
    layout.addWidget(labelBanner,        3, 0, 1, 1);
    layout.addWidget(texteditBanner,     3, 1, 1, 3);
    layout.addWidget(labelAnswer,        4, 0, 1, 1);
    layout.addWidget(texteditAnswer,     4, 1, 1, 3);
    layout.addWidget(labelEncryptKey,    5, 0, 1, 1);
    layout.addWidget(textlineEncryptKey, 5, 1, 1, 2);
    layout.addWidget(buttonEncryptKey,   5, 3, 1, 1);
    layout.addWidget(checkMtls,          6, 0, 1, 1);
    layout.addWidget(howButton,          6, 1, 1, 1);
    layout.addWidget(caCertSelector,     6, 2, 1, 2);
    layout.addWidget(srvKeySelector,     7, 0, 1, 2);
    layout.addWidget(srvCertSelector,    7, 2, 1, 2);
    layout.addWidget(clientKeySelector,  8, 0, 1, 2);
    layout.addWidget(clientCertSelector, 8, 2, 1, 2);

    form.connect(buttonEncryptKey, "clicked", function() { textlineEncryptKey.setText( ax.random_string(32, "hex") ); });

    form.connect(checkMtls, "stateChanged", function() {
        if(caCertSelector.getEnabled()) {
            caCertSelector.setEnabled(false);
            srvCertSelector.setEnabled(false);
            srvKeySelector.setEnabled(false);
            clientCertSelector.setEnabled(false);
            clientKeySelector.setEnabled(false);
        } else {
            caCertSelector.setEnabled(true);
            srvCertSelector.setEnabled(true);
            srvKeySelector.setEnabled(true);
            clientCertSelector.setEnabled(true);
            clientKeySelector.setEnabled(true);
        }
    });

    form.connect(howButton, "clicked", function() {
        let dialog = form.create_dialog("Generate mTLS certificates");

        let infoText = form.create_textmulti();
        infoText.setReadOnly(true);
        infoText.appendText("# CA cert");
        infoText.appendText("openssl genrsa -out ca.key 2048");
        infoText.appendText("openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj \"/CN=Test CA\"\n");
        infoText.appendText("# server cert and key");
        infoText.appendText("openssl genrsa -out server.key 2048");
        infoText.appendText("openssl req -new -key server.key -out server.csr -subj \"/CN=localhost\"");
        infoText.appendText("openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256\n");
        infoText.appendText("# client cert and key");
        infoText.appendText("openssl genrsa -out client.key 2048");
        infoText.appendText("openssl req -new -key client.key -out client.csr -subj \"/CN=client\"");
        infoText.appendText("openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256");

        let layout = form.create_vlayout();
        layout.addWidget(infoText);

        dialog.setLayout(layout);
        dialog.setSize(1100, 340);
        dialog.exec()
    });

    let container = form.create_container()
    container.put("host_bind", comboHostBind)
    container.put("port_bind", spinPort)
    container.put("callback_addresses", texteditCallback)
    container.put("timeout", spinTimeout)
    container.put("tcp_banner", texteditBanner)
    container.put("error_answer", texteditAnswer)
    container.put("encrypt_key", textlineEncryptKey);
    container.put("ssl", checkMtls)
    container.put("ca_cert", caCertSelector)
    container.put("server_cert", srvCertSelector)
    container.put("server_key", srvKeySelector)
    container.put("client_cert", clientCertSelector)
    container.put("client_key", clientKeySelector)

    let panel = form.create_panel()
    panel.setLayout(layout)

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 650,
        ui_width: 650
    }
}

function AgentUI()
{
    let labelCallback = form.create_label("Callback address:");
    let texteditCallback = form.create_textline("192.168.3.250:9000");

    let layout = form.create_gridlayout();
    layout.addWidget(labelCallback, 0, 0, 1, 1);
    layout.addWidget(texteditCallback, 0, 1, 1, 1);

    let container = form.create_container();
    container.put("callback", texteditCallback);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 200,
        ui_width: 400
    }
}

function GenerateUI(listenerType)
{
    let labelOS = form.create_label("OS:");
    let comboOS = form.create_combo()
    comboOS.addItems(["windows", "linux", "macos"]);

    let labelArch = form.create_label("Arch:");
    let comboArch = form.create_combo()
    comboArch.addItems(["amd64", "arm64"]);

    let labelFormat = form.create_label("Format:");
    let comboFormat = form.create_combo()
    comboFormat.addItems(["Binary EXE"]);

    let checkWin7 = form.create_check("Windows 7 support");

    let hline = form.create_hline()

    let labelReconnTimeout = form.create_label("Reconnect timeout:");
    let textReconnTimeout = form.create_textline("10");
    textReconnTimeout.setPlaceholder("seconds")

    let labelReconnCount = form.create_label("Reconnect count:");
    let spinReconnCount = form.create_spin();
    spinReconnCount.setRange(0, 1000000000);
    spinReconnCount.setValue(1000000000);

    let layout = form.create_gridlayout();
    layout.addWidget(labelOS, 0, 0, 1, 1);
    layout.addWidget(comboOS, 0, 1, 1, 1);
    layout.addWidget(labelArch, 1, 0, 1, 1);
    layout.addWidget(comboArch, 1, 1, 1, 1);
    layout.addWidget(labelFormat, 2, 0, 1, 1);
    layout.addWidget(comboFormat, 2, 1, 1, 1);
    layout.addWidget(checkWin7, 3, 1, 1, 1);
    layout.addWidget(hline, 4, 0, 1, 2);
    layout.addWidget(labelReconnTimeout, 5, 0, 1, 1);
    layout.addWidget(textReconnTimeout, 5, 1, 1, 1);
    layout.addWidget(labelReconnCount, 6, 0, 1, 1);
    layout.addWidget(spinReconnCount, 6, 1, 1, 1);

    form.connect(comboOS, "currentTextChanged", function(text) {
        if(text == "windows") {
            comboFormat.setItems(["Binary EXE"]);
            checkWin7.setVisible(true);
        }
        else if (text == "linux") {
            comboFormat.setItems(["Binary .ELF"]);
            checkWin7.setVisible(false);
        }
        else {
            comboFormat.setItems(["Binary Mach-O"]);
            checkWin7.setVisible(false);
        }
    });

    let container = form.create_container()
    container.put("os", comboOS)
    container.put("arch", comboArch)
    container.put("format", comboFormat)
    container.put("reconn_timeout", textReconnTimeout)
    container.put("reconn_count", spinReconnCount)
    container.put("win7_support", checkWin7)

    let panel = form.create_panel()
    panel.setLayout(layout)

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 450,
        ui_width: 550
    }
}
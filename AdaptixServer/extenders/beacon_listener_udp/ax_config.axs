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

    form.connect(buttonEncryptKey, "clicked", function() { textlineEncryptKey.setText( ax.random_string(32, "hex") ); });

    let container = form.create_container()
    container.put("host_bind", comboHostBind)
    container.put("port_bind", spinPort)
    container.put("callback_addresses", texteditCallback)
    container.put("timeout", spinTimeout)
    container.put("tcp_banner", texteditBanner)
    container.put("error_answer", texteditAnswer)
    container.put("encrypt_key", textlineEncryptKey);

    let panel = form.create_panel()
    panel.setLayout(layout)

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 650,
        ui_width: 650
    }
}
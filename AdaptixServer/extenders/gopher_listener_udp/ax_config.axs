/// Gopher QUIC listener

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
    spinPort.setValue(4444);
    spinPort.setEnabled(mode_create)

    let labelCallback = form.create_label("Callback addresses:");
    let texteditCallback = form.create_textmulti();
    texteditCallback.setPlaceholder("192.168.1.1:4444\nserver2.com:5555");

    let labelTimeout = form.create_label("Timeout (sec):");
    let spinTimeout = form.create_spin();
    spinTimeout.setRange(1, 1000000);
    spinTimeout.setValue(10);

    let labelSleep = form.create_label("Sleep (ms):");
    let spinSleep = form.create_spin();
    spinSleep.setRange(0, 60000);
    spinSleep.setValue(0);

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
    layout.addWidget(labelSleep,         3, 0, 1, 1);
    layout.addWidget(spinSleep,          3, 1, 1, 3);
    layout.addWidget(labelEncryptKey,    4, 0, 1, 1);
    layout.addWidget(textlineEncryptKey, 4, 1, 1, 2);
    layout.addWidget(buttonEncryptKey,   4, 3, 1, 1);

    form.connect(buttonEncryptKey, "clicked", function() { textlineEncryptKey.setText( ax.random_string(32, "hex") ); });

    let container = form.create_container()
    container.put("host_bind", comboHostBind)
    container.put("port_bind", spinPort)
    container.put("callback_addresses", texteditCallback)
    container.put("timeout", spinTimeout)
    container.put("sleep", spinSleep)
    container.put("encrypt_key", textlineEncryptKey);

    let panel = form.create_panel()
    panel.setLayout(layout)

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 350,
        ui_width: 650
    }
}

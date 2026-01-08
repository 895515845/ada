/// Gopher ICMP listener
/// Gopher ICMP监听器配置界面

function ListenerUI(mode_create)
{
    // 监听地址选择 - Listen address selection
    let labelListenAddr = form.create_label("Listen Address (Bind):");
    let comboListenAddr = form.create_combo();
    comboListenAddr.setEnabled(mode_create)
    comboListenAddr.clear();
    let addrs = ax.interfaces();
    for (let item of addrs) { comboListenAddr.addItem(item); }

    // 回调地址 - Callback addresses
    let labelCallback = form.create_label("Callback addresses:");
    let texteditCallback = form.create_textmulti();
    texteditCallback.setPlaceholder("192.168.1.1\nserver2.com");

    // 超时设置 - Timeout setting
    let labelTimeout = form.create_label("Timeout (sec):");
    let spinTimeout = form.create_spin();
    spinTimeout.setRange(1, 1000000);
    spinTimeout.setValue(10);

    // 最大分片大小 - Max fragment size
    let labelFragSize = form.create_label("Max Fragment Size:");
    let spinFragSize = form.create_spin();
    spinFragSize.setRange(100, 65000);
    spinFragSize.setValue(65000);
    spinFragSize.setEnabled(mode_create);

    // Sleep时间 - Sleep time (heartbeat interval)
    let labelSleepTime = form.create_label("Sleep Time (sec):");
    let spinSleepTime = form.create_spin();
    spinSleepTime.setRange(1, 3600);
    spinSleepTime.setValue(5);
    spinSleepTime.setEnabled(mode_create);

    // 错误响应 - Error answer
    let labelAnswer = form.create_label("Error answer:");
    let texteditAnswer = form.create_textmulti("Connection error...\n");

    // 加密密钥 - Encryption key
    let labelEncryptKey = form.create_label("Encryption key:");
    let textlineEncryptKey = form.create_textline(ax.random_string(32, "hex"));
    textlineEncryptKey.setEnabled(mode_create)
    let buttonEncryptKey = form.create_button("Generate");
    buttonEncryptKey.setEnabled(mode_create)

    // ICMP说明标签 - ICMP description label
    let labelInfo = form.create_label("Note: ICMP listener requires root/admin privileges");

    // 布局设置 - Layout setup
    let layout = form.create_gridlayout();
    layout.addWidget(labelListenAddr,      0, 0, 1, 1);
    layout.addWidget(comboListenAddr,      0, 1, 1, 3);
    layout.addWidget(labelCallback,        1, 0, 1, 1);
    layout.addWidget(texteditCallback,     1, 1, 1, 3);
    layout.addWidget(labelTimeout,         2, 0, 1, 1);
    layout.addWidget(spinTimeout,          2, 1, 1, 3);
    layout.addWidget(labelFragSize,        3, 0, 1, 1);
    layout.addWidget(spinFragSize,         3, 1, 1, 3);
    layout.addWidget(labelSleepTime,       4, 0, 1, 1);
    layout.addWidget(spinSleepTime,        4, 1, 1, 3);
    layout.addWidget(labelAnswer,          5, 0, 1, 1);
    layout.addWidget(texteditAnswer,       5, 1, 1, 3);
    layout.addWidget(labelEncryptKey,      6, 0, 1, 1);
    layout.addWidget(textlineEncryptKey,   6, 1, 1, 2);
    layout.addWidget(buttonEncryptKey,     6, 3, 1, 1);
    layout.addWidget(labelInfo,            7, 0, 1, 4);

    // 生成密钥按钮事件 - Generate key button event
    form.connect(buttonEncryptKey, "clicked", function() {
        textlineEncryptKey.setText( ax.random_string(32, "hex") );
    });

    // 容器设置 - Container setup
    let container = form.create_container()
    container.put("listen_addr", comboListenAddr)
    container.put("callback_addresses", texteditCallback)
    container.put("timeout", spinTimeout)
    container.put("max_fragment_size", spinFragSize)
    container.put("sleep_time", spinSleepTime)
    container.put("error_answer", texteditAnswer)
    container.put("encrypt_key", textlineEncryptKey);

    // 面板设置 - Panel setup
    let panel = form.create_panel()
    panel.setLayout(layout)

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 500,
        ui_width: 650
    }
}

from iawp.classify.mock import MockClassifier


def classify(**state):
    return MockClassifier().classify(state)


def test_own_name_beats_interpreter_exe():
    # Seen on the lab VM: as root, exe is readable and says python3, which must
    # not hide the telling process name.
    for exe in ("(unreadable without root)", "/usr/bin/python3.12"):
        r = classify(process_name="unattended-upgr", executable=exe,
                     command_line="/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown")
        assert r.cls == "background" and r.enough_info > 0.5


def test_generic_interpreter_uses_arguments():
    assert classify(process_name="python3", executable="/usr/bin/python3.12",
                    command_line="python3 train.py").cls == "batch-compute"
    assert classify(process_name="python3", executable="/usr/bin/python3.12",
                    command_line="python3 thing.py").enough_info < 0.5

import sys
import os
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from SSH.SSHTransportLayerProtocol import SSH_Transport_Layer_Protocol_Utils

def test_generate_id_str():
    pass_tests = [
        ("wwwww", None),
        ("billsSSH_3.6.3q3", None),
        ("exampleSoftware", "123456"),
        ("skks~!@", None),
        ("skks", "kk#"),
        ("skks", "kk@"),
        ("skks", "kk a"),
        ("skks", "kk "),
        ("skks", "kk-")]
    fail_tests = [
        ("exampleSoftware", ""),
        ("", None),
        ("skks-", None),
        ("skks\n", None),
        ("skks\0", "kk"),
        ("skks", "kk\0"),
        ("skks", "kk\n")]
    
    for t1,t2 in pass_tests:
        try:
            s = SSH_Transport_Layer_Protocol_Utils.create_id_str(t1,t2)
        except:
            print(f"Error: {repr(t1)} and {repr(t2)} should have passed the test and didn't!")

    for t1,t2 in fail_tests:
        try:
            s = SSH_Transport_Layer_Protocol_Utils.create_id_str(t1,t2)
            print(f"Error: {repr(t1)} and {repr(t2)} should have passed the test and didn't!")
        except:
            pass

def test_check_id_str():
    pass_tests = [
        "SSH-2.0-GuilleSSH hello\r\n",
        "SSH-2.0-exampleSoftware\r\n",
        "SSH-2.0-exampleSoftware 123@#$#@-m 6\r\n",
        "SSH-2.0-exampleSoftwa@@@re 123456\r\n",
        "SSH-2.0-exampleSo__.@ftware 123456\r\n",
        "SSH-2.0-exampleSoftware 123456\r\n",
        "SSH-2.0-example Software 123456\r\n"]
    fail_tests = [ 
        "SSH-2.0-exampleSoftware 123\n456\r\n",   # Extra \n
        "SSH-2.0-billsSSH_3.6.3q3 erje\0\r\n",  # Null char
        "SSH-2.0-bill\0SSH_3.6.3q3\r\n",  # Null char
        "SSH-2.0-bill\0SSH_3.6.3q3\r\n\r\n",  # Extra \r\n
        "SSH-2.0-bills-SSH_3.6.3q3\r\n",  # Minus sign !!!
        "SSH-2.0-billsSS\rH_3.6.3q3\r\n",  # Non printable
        "SSH-2.0-billsSSH_3.6.3q3 4434\r\r\n",  # Non printable
        "SSH-1.99-exampleSoftware\r\n",  # Invalid (wrong protocol version)
        "SSH-2.0-invalid-software\n",  # Invalid (missing \r)
        "SSH-2.0-invalid-software\r\nExtra data",  # Invalid (extra data)
    ]

    for test in pass_tests:
        if not SSH_Transport_Layer_Protocol_Utils.check_id_str(test):
            print(f"Error: {repr(test)} should've passed the test and didn't!")
 
    print("==============================================")
    
    for test in fail_tests:
        if SSH_Transport_Layer_Protocol_Utils.check_id_str(test):
            print(f"Error: {repr(test)} passed the test and shouldn't have!")

def test_id_string():
    pass_tests = [
        ("wwwww", None),
        ("billsSSH_3.6.3q3", None),
        ("exampleSoftware", "123456"),
        ("skks~!@", None),
        ("skks", "kk#"),
        ("skks", "kk@"),
        ("skks", "kk a"),
        ("skks", "kk "),
        ("skks", "kk-")]
    
    for t1,t2 in pass_tests:
        s = SSH_Transport_Layer_Protocol_Utils.create_id_str("2.0", t1,t2)
        if not SSH_Transport_Layer_Protocol_Utils.check_id_str(s):
            print(f"Error: generated string '{repr(s)}' didn't pass th check!")


def main():
    test_check_id_str()

main()
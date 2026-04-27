from monitor import calculate_behavior_risk


def calculate_risk(session_data, current_ip):
    result = calculate_behavior_risk(session_data, current_ip)
    return result["risk"], result["reasons"]

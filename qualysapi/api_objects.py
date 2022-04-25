import datetime

from lxml import objectify


class Host:
    def __init__(self, dns, id, ip, last_scan, netbios, os, tracking_method):
        self.dns = str(dns)
        self.id = int(id)
        self.ip = str(ip)
        try:
            last_scan = str(last_scan).replace("T", " ").replace("Z", "").split(" ")
            date = last_scan[0].split("-")
            time = last_scan[1].split(":")
            self.last_scan = datetime.datetime(
                int(date[0]), int(date[1]), int(date[2]), int(time[0]), int(time[1]), int(time[2])
            )
        except IndexError:
            self.last_scan = "never"
        self.netbios = str(netbios)
        self.os = str(os)
        self.tracking_method = str(tracking_method)

    def __repr__(self):
        return f"ip: {self.ip}, qualys_id: {self.id}, dns: {self.dns}"


class VirtualHost:
    def __init__(self, fqdn, ip, network_id, port):
        self.fqdn = fqdn
        self.ip = ip
        self.network_id = network_id
        self.port = port

    def __repr__(self):
        return (
            f"vhost: {self.fqdn}, ip: {self.ip}, network_id: {self.network_id}, port: {self.port}"
        )


class AssetGroup:
    def __init__(
        self, business_impact, id, last_update, scanips, scandns, scanner_appliances, title
    ):
        self.business_impact = str(business_impact)
        self.id = int(id)
        self.last_update = str(last_update)
        self.scanips = scanips
        self.scandns = scandns
        self.scanner_appliances = scanner_appliances
        self.title = str(title)

    def addAsset(self, conn, ip):
        call = "/api/2.0/fo/asset/group/"
        parameters = {"action": "edit", "id": self.id, "add_ips": ip}
        conn.request(call, parameters)
        self.scanips.append(ip)

    def setAssets(self, conn, ips):
        call = "/api/2.0/fo/asset/group/"
        parameters = {"action": "edit", "id": self.id, "set_ips": ips}
        conn.request(call, parameters)

    def __repr__(self):
        return f"qualys_id: {self.id}, title: {self.title}"


class ReportTemplate:
    def __init__(self, isGlobal, id, last_update, template_type, title, type, user):
        self.isGlobal = int(isGlobal)
        self.id = int(id)
        self.last_update = str(last_update).replace("T", " ").replace("Z", "").split(" ")
        self.template_type = template_type
        self.title = title
        self.type = type
        self.user = user.LOGIN

    def __repr__(self):
        return f"qualys_id: {self.id}, title: {self.title}"


class Report:
    def __init__(
        self,
        expiration_datetime,
        id,
        launch_datetime,
        output_format,
        size,
        status,
        type,
        user_login,
        title="",
    ):
        self.expiration_datetime = (
            str(expiration_datetime).replace("T", " ").replace("Z", "").split(" ")
        )
        self.id = int(id)
        self.launch_datetime = str(launch_datetime).replace("T", " ").replace("Z", "").split(" ")
        self.output_format = output_format
        self.size = size
        self.status = status.STATE
        self.type = type
        self.user_login = user_login
        self.title = title

    def __repr__(self):
        return f"qualys_id: {self.id}, title: {self.title}"

    def download(self, conn):
        call = "/api/2.0/fo/report"
        parameters = {"action": "fetch", "id": self.id}
        if self.status == "Finished":
            return conn.request(call, parameters)


class Scan:
    def __init__(
        self,
        assetgroups,
        duration,
        launch_datetime,
        option_profile,
        processed,
        ref,
        status,
        target,
        title,
        type,
        user_login,
    ):
        self.assetgroups = assetgroups
        self.duration = str(duration)
        launch_datetime = str(launch_datetime).replace("T", " ").replace("Z", "").split(" ")
        date = launch_datetime[0].split("-")
        time = launch_datetime[1].split(":")
        self.launch_datetime = datetime.datetime(
            int(date[0]), int(date[1]), int(date[2]), int(time[0]), int(time[1]), int(time[2])
        )
        self.option_profile = str(option_profile)
        self.processed = int(processed)
        self.ref = str(ref)
        self.status = str(status.STATE)
        self.target = str(target).split(", ")
        self.title = str(title)
        self.type = str(type)
        self.user_login = str(user_login)

    def __repr__(self):
        return (
            f"qualys_ref: {self.ref}, title: {self.title}, option_profile: {self.option_profile}"
        )

    def cancel(self, conn):
        cancelled_statuses = ["Cancelled", "Finished", "Error"]
        if any(self.status in s for s in cancelled_statuses):
            raise ValueError("Scan cannot be cancelled because its status is " + self.status)
        else:
            call = "/api/2.0/fo/scan/"
            parameters = {"action": "cancel", "scan_ref": self.ref}
            conn.request(call, parameters)

            parameters = {"action": "list", "scan_ref": self.ref, "show_status": 1}
            self.status = objectify.fromstring(
                conn.request(call, parameters).encode("utf-8")
            ).RESPONSE.SCAN_LIST.SCAN.STATUS.STATE

    def pause(self, conn):
        if self.status != "Running":
            raise ValueError("Scan cannot be paused because its status is " + self.status)
        else:
            call = "/api/2.0/fo/scan/"
            parameters = {"action": "pause", "scan_ref": self.ref}
            conn.request(call, parameters)

            parameters = {"action": "list", "scan_ref": self.ref, "show_status": 1}
            self.status = objectify.fromstring(
                conn.request(call, parameters).encode("utf-8")
            ).RESPONSE.SCAN_LIST.SCAN.STATUS.STATE

    def resume(self, conn):
        if self.status != "Paused":
            raise ValueError("Scan cannot be resumed because its status is " + self.status)
        else:
            call = "/api/2.0/fo/scan/"
            parameters = {"action": "resume", "scan_ref": self.ref}
            conn.request(call, parameters)

            parameters = {"action": "list", "scan_ref": self.ref, "show_status": 1}
            self.status = objectify.fromstring(
                conn.request(call, parameters).encode("utf-8")
            ).RESPONSE.SCAN_LIST.SCAN.STATUS.STATE

class Ticket:
    def __init__(
        self,
        number,
        assignee,
        creation_datetime,
        detection,
        due_datetime,
        history_list,
        invalid,
        state,
        status,
        stats,
        vulninfo
    ):
        self.number = number
        self.assignee = assignee
        creation_datetime = str(creation_datetime).replace("T", " ").replace("Z", "").split(" ")
        creation_date = creation_datetime[0].split("-")
        creation_time = creation_datetime[1].split(":")
        self.creation_datetime = datetime.datetime(
            int(creation_date[0]), int(creation_date[1]), int(creation_date[2]), int(creation_time[0]), int(creation_time[1]), int(creation_time[2])
        )
        self.detection = detection
        due_datetime = str(due_datetime).replace("T", " ").replace("Z", "").split(" ")
        due_date = due_datetime[0].split("-")
        due_time = due_datetime[1].split(":")
        self.due_datetime = datetime.datetime(
            int(due_date[0]), int(due_date[1]), int(due_date[2]), int(due_time[0]), int(due_time[1]), int(due_time[2])
        )
        self.history_list = history_list
        self.invalid = bool(invalid)
        self.state = str(state.text)
        self.status = str(status.text)
        self.stats = stats
        self.vulninfo = vulninfo

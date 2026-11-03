# Cloud Apps and Third-party Apps

## Cloud Apps

Cloud Apps manages **Amazon Web Services**, **Google Cloud** and **Microsoft Azure** from your Pi.
The servers, databases and computing run in the cloud. The Pi sends the commands through each
provider's official command-line tool, so it needs no extra power, and the cloud resources are
billed by the provider as usual.

Each provider page installs its tool in one click the first time:

| Provider | Tool | Where it comes from |
| -------- | ---- | ------------------- |
| AWS | AWS CLI v2 (`aws`) | Debian's `awscli` package |
| Google Cloud | Google Cloud CLI (`gcloud`, `gsutil`, `bq`) | Google's apt repository, added by the installer |
| Azure | Azure CLI (`az`) | Debian's `azure-cli` package |

### Connecting an account

Create an account for the panel at the provider, with only the rights it needs, and paste its
sign-in on the provider page. The page shows the steps.

- **AWS**: an IAM user's access key (access key ID and secret) and a default region.
- **Google Cloud**: a service account key (the JSON file) and the project ID.
- **Azure**: a service principal (tenant ID, application ID and a client secret) and, optionally, a subscription.

The panel checks the sign-in right away and keeps it in `/var/lib/aurora/cloud/<provider>/`,
readable by root only. It is never shown again and never written to the Activity Log.
**Disconnect** removes it from the server.

To use the same sign-in by hand in the Terminal, copy the line the page shows and put it in front
of a command, for example `AWS_SHARED_CREDENTIALS_FILE=… AWS_CONFIG_FILE=… aws s3 ls`.

### What each page does

| What for | AWS | Google Cloud | Azure | On the page |
| -------- | --- | ------------ | ----- | ----------- |
| Virtual servers | EC2 | Compute Engine | Virtual Machines | List, start, stop |
| Files and backups | S3 | Cloud Storage | Blob Storage | Browse, push and pull files |
| Databases | RDS / Aurora | Cloud SQL | Azure SQL | List |
| Kubernetes | EKS | GKE | AKS | List |
| Code that runs on events | Lambda | Cloud Run functions | Azure Functions | List |
| Containers | ECS / Fargate | Cloud Run | Container Instances | List |
| Big data analytics | Redshift | BigQuery | Synapse Analytics | List |

The match between providers is approximate. Everything else opens in the provider's console.

On Azure, **Stop** deallocates the virtual machine, because a stopped but allocated machine is
still billed for its compute.

Copies between the Pi and cloud storage only add and update files. They never delete anything on
either side. The Pi side is limited to the folders the File Manager may open.

### Free options

Each page lists what the provider offers for free, with a link to its current terms. Free amounts
have limits, and anything beyond them is billed.

## Third-party Apps

Third-party Apps connects **Google Drive** and **Google Photos** to the Pi. Copies run through
rclone, which the page installs in one click.

### Signing in

Google only sends a sign-in back to a public address, or to `127.0.0.1` on the computer with the
browser, never to a home server's LAN address. So the sign-in takes one paste:

1. Press **Connect**, then **Sign in with Google**. A Google tab opens.
2. Sign in and allow access. Google then opens a page on `127.0.0.1` that can't load. That is expected.
3. Copy that page's whole address from the address bar, paste it into the panel and press **Finish**.

By default the sign-in uses rclone's shared Google app. For better speed, use your own: in the
Google Cloud console enable the Google Drive API or the Photos Library API, create an OAuth client
ID of type **Desktop app**, and paste its ID and secret under **Use my own Google app**.

Tokens are kept in `/var/lib/aurora/connectors/`, readable by root only. **Disconnect** removes
them from the server. To withdraw the access at Google as well, open
[your Google account's connections](https://myaccount.google.com/connections).

### Copying

Pick a file or folder on one side, open the folder it should go to on the other, then **Push**
(to Google) or **Pull** (to the Pi). New and changed files are copied, and nothing is deleted.

### Google Photos limits

Since 31 March 2025 Google lets apps see only the photos and albums they uploaded themselves.

- **Push** works for all your photos and videos. Push into `upload` to add them to your library, or
  into `album/<name>` to make or fill an album.
- **Pull** brings back what this server uploaded, from `album` or `media`.

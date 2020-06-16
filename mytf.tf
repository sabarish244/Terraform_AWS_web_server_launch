
// Setting up the cloud provider

provider "aws" {
	region = "ap-south-1"
	profile = "sabarish"
	}

// Creating a keypair
 
resource "tls_private_key" "tf_key" {
	algorithm = "RSA"
	rsa_bits = 4096
	}
	
resource "aws_key_pair" "newkey" {
	key_name = "tfkey"
	public_key = "${tls_private_key.tf_key.public_key_openssh}"
}

resource "local_file" "key_file" {
	content = "${tls_private_key.tf_key.private_key_pem}"
	filename = "tfkey.pem"
	}

// Creating a security group which would allow port 80

resource "aws_security_group" "allow_port80" {
  name        = "allow_80port"
  description = "Allow inbound traffic"
  vpc_id      = "vpc-41796629"

  ingress {
    description = "SSH Config"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP config"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "my_secgrp_allow_port80"
  }
}


//Launching EC2 instance with our security group and key pair created above

resource "aws_instance" "my_web_instance" {
	ami = "ami-0447a12f28fddb066"
	instance_type = "t2.micro"
	availability_zone = "ap-south-1a"
	key_name = "${aws_key_pair.newkey.key_name}"
	security_groups = ["${aws_security_group.allow_port80.name}"]
	
	connection{
		type = "ssh"
		port = 22
		user = "ec2-user"
		private_key = "${tls_private_key.tf_key.private_key_pem}"
		host = "${aws_instance.my_web_instance.public_ip}"
	} 

	provisioner "remote-exec"{
	inline = [
	"sudo yum install httpd php git -y",
	"sudo systemctl restart httpd",
	"sudo systemctl enable httpd",
	]
	}
	
	tags = {
		Name="my_web"
	}
	} 	
	
	
// Launching a EBS and mounting it

resource "aws_ebs_volume" "my_tf_vol" {
	availability_zone = "${aws_instance.my_web_instance.availability_zone}"
	size = 1
	
	tags = {
	name = "tf_vol"
	}
}

resource "aws_volume_attachment" "my_tf_vol_attach" {
	device_name = "/dev/sdf"
	volume_id = "${aws_ebs_volume.my_tf_vol.id}"
	instance_id = "${aws_instance.my_web_instance.id}"
	force_detach = true
	}


// Mounting The EBS to the EC2 and cloning the repo inside the instance
	
resource "null_resource" "ebs_mount"{

	depends_on = [
		aws_volume_attachment.my_tf_vol_attach,aws_instance.my_web_instance
		]
	connection {
		type = "ssh"
		port = 22
		user = "ec2-user"
		private_key = "${tls_private_key.tf_key.private_key_pem}"
		host = "${aws_instance.my_web_instance.public_ip}"
	}
	provisioner "remote-exec"{
	
	inline = [
				"sudo mkfs.ext4 /dev/sdf",
				"sudo mount /dev/sdf /var/www/html",
				"sudo rm -rf /var/www/html/*",
				"sudo git clone https://github.com/sabarish244/Terraform_AWS_web_server_launch.git /var/www/html/"
				]
}
}


// Creating a S3 bucket and adding a image inside the bucket

resource "aws_s3_bucket" "tfbucket" {
	bucket = "tfawsbucket"
	acl = "public-read"
	}
	
resource "aws_s3_bucket_object" "tfbucketobject" {
	bucket = "${aws_s3_bucket.tfbucket.bucket}"
	key = "tfaws.jpg"
	source = "C:/Users/ADMIN/Downloads/tfaws.jpg"
	acl = "public-read"
	}
	
	
//Creating a cloudfront distribution

locals {
s3_origin_id = aws_s3_bucket.tfbucket.id
}

resource "aws_cloudfront_distribution" "cloudfronttf" {
	depends_on = [
					aws_s3_bucket_object.tfbucketobject,
	]

	origin {
		domain_name = "${aws_s3_bucket.tfbucket.bucket_regional_domain_name}"
		origin_id = "${local.s3_origin_id}"
		}
	enabled = true
	is_ipv6_enabled = true
	comment = "Cloud Front S3 distribution"
	
	default_cache_behavior{
	allowed_methods = ["DELETE",  "GET" , "HEAD" , "OPTIONS", "PATCH" , "POST", "PUT"]
	cached_methods = ["GET" , "HEAD"]
	target_origin_id = local.s3_origin_id
	
	forwarded_values{
	query_string = false
	cookies {
	forward = "none"
	}
	}
	viewer_protocol_policy = "allow-all"
	min_ttl = 0
	default_ttl = 3600
	max_ttl = 86400
	}
	restrictions {
	geo_restriction {
	restriction_type = "whitelist"
	locations = ["IN"]
	}
	}
	
	tags = {
	Name = "my_webserver1"
	Environment = "production_main"
	}
	
	viewer_certificate {
	cloudfront_default_certificate = true
	}
	retain_on_delete = true
	}

	
// Changing the S3 image inside the webpage code

		resource "null_resource"  "null" {
		depends_on = [
		aws_instance.my_web_instance,aws_cloudfront_distribution.cloudfronttf
		]
	connection {
		type = "ssh"
		port = 22
		user = "ec2-user"
		private_key = "${tls_private_key.tf_key.private_key_pem}"
		host = "${aws_instance.my_web_instance.public_ip}"
	}
	provisioner "remote-exec"{
	
	inline = [
				"sudo su << EOF",
				"echo '<img src='https://${aws_cloudfront_distribution.cloudfronttf.domain_name}/tfaws.jpg' height = '200px' width='200px'' >> /var/www/html/webpage.html ",
				"EOF"
	]
	
	}
	}
// Creating EBS snapshot

resource "aws_ebs_snapshot" "tf_snapshot" {
	volume_id = "${aws_ebs_volume.my_tf_vol.id}"
	
	tags = {
	Name = "My_TF_SNAPSHOT"
	}
}
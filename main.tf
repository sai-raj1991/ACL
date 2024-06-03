terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.52.0"
    }
  }
}

# Define providers for each region
provider "aws" {
  alias  = "us_east_1"
  region = var.aws_regions["us_east_1"]
}

provider "aws" {
  alias  = "us_east_2"
  region = var.aws_regions["us_east_2"]
}

provider "aws" {
  alias  = "us_west_1"
  region = var.aws_regions["us_west_1"]
}



provider "aws" {
  alias  = "af_south_1"
  region = var.aws_regions["af_south_1"]
}

provider "aws" {
  alias  = "ap_east_1"
  region = var.aws_regions["ap_east_1"]
}

provider "aws" {
  alias  = "ap_southeast_3"
  region = var.aws_regions["ap_southeast_3"]
}

provider "aws" {
  alias  = "ap_south_1"
  region = var.aws_regions["ap_south_1"]
}

provider "aws" {
  alias  = "us_west_2"
  region = var.aws_regions["us_west_2"]
}

provider "aws" {
  alias  = "ap_northeast_1"
  region = var.aws_regions["ap_northeast_1"]
}


provider "aws" {
  alias  = "ap_northeast_2"
  region = var.aws_regions["ap_northeast_2"]
}

provider "aws" {
  alias  = "ap_southeast_1"
  region = var.aws_regions["ap_southeast_1"]
}

provider "aws" {
  alias  = "ap_southeast_2"
  region = var.aws_regions["ap_southeast_2"]
}

provider "aws" {
  alias  = "ca_central_1"
  region = var.aws_regions["ca_central_1"]
}

provider "aws" {
  alias  = "eu_central_1"
  region = var.aws_regions["eu_central_1"]
}

provider "aws" {
  alias  = "eu_west_1"
  region = var.aws_regions["eu_west_1"]
}

provider "aws" {
  alias  = "eu_west_2"
  region = var.aws_regions["eu_west_2"]
}

provider "aws" {
  alias  = "eu_west_3"
  region = var.aws_regions["eu_west_3"]
}

provider "aws" {
  alias  = "eu_north_1"
  region = var.aws_regions["eu_north_1"]
}

provider "aws" {
  alias  = "eu_south_1"
  region = var.aws_regions["eu_south_1"]
}

provider "aws" {
  alias  = "me_south_1"
  region = var.aws_regions["me_south_1"]
}

provider "aws" {
  alias  = "sa_east_1"
  region = var.aws_regions["sa_east_1"]
}

# Import the default network ACL for each region
resource "aws_default_network_acl" "default_us_east_1" {
  provider               = aws.us_east_1
  default_network_acl_id = var.default_network_acl_ids["us_east_1"]
}

resource "aws_default_network_acl" "default_us_east_2" {
  provider               = aws.us_east_2
  default_network_acl_id = var.default_network_acl_ids["us_east_2"]
}

resource "aws_default_network_acl" "default_us_west_1" {
  provider               = aws.us_west_1
  default_network_acl_id = var.default_network_acl_ids["us_west_1"]
}

resource "aws_default_network_acl" "default_us_west_2" {
  provider               = aws.us_west_2
  default_network_acl_id = var.default_network_acl_ids["us_west_2"]
}

resource "aws_default_network_acl" "default_af_south_1" {
  provider               = aws.af_south_1
  default_network_acl_id = var.default_network_acl_ids["af_south_1"]
}

resource "aws_default_network_acl" "default_ap_east_1" {
  provider               = aws.ap_east_1
  default_network_acl_id = var.default_network_acl_ids["ap_east_1"]
}

resource "aws_default_network_acl" "default_ap_southeast_3" {
  provider               = aws.ap_southeast_3
  default_network_acl_id = var.default_network_acl_ids["ap_southeast_3"]
}

resource "aws_default_network_acl" "default_ap_south_1" {
  provider               = aws.ap_south_1
  default_network_acl_id = var.default_network_acl_ids["ap_south_1"]
}

resource "aws_default_network_acl" "default_ap_northeast_1" {
  provider               = aws.ap_northeast_1
  default_network_acl_id = var.default_network_acl_ids["ap_northeast_1"]
}

resource "aws_default_network_acl" "default_ap_northeast_2" {
  provider               = aws.ap_northeast_2
  default_network_acl_id = var.default_network_acl_ids["ap_northeast_2"]
}

resource "aws_default_network_acl" "default_ap_southeast_1" {
  provider               = aws.ap_southeast_1
  default_network_acl_id = var.default_network_acl_ids["ap_southeast_1"]
}

resource "aws_default_network_acl" "default_ap_southeast_2" {
  provider               = aws.ap_southeast_2
  default_network_acl_id = var.default_network_acl_ids["ap_southeast_2"]
}

resource "aws_default_network_acl" "default_ca_central_1" {
  provider               = aws.ca_central_1
  default_network_acl_id = var.default_network_acl_ids["ca_central_1"]
}

resource "aws_default_network_acl" "default_eu_central_1" {
  provider               = aws.eu_central_1
  default_network_acl_id = var.default_network_acl_ids["eu_central_1"]
}

resource "aws_default_network_acl" "default_eu_west_1" {
  provider               = aws.eu_west_1
  default_network_acl_id = var.default_network_acl_ids["eu_west_1"]
}

resource "aws_default_network_acl" "default_eu_west_2" {
  provider               = aws.eu_west_2
  default_network_acl_id = var.default_network_acl_ids["eu_west_2"]
}

resource "aws_default_network_acl" "default_eu_west_3" {
  provider               = aws.eu_west_3
  default_network_acl_id = var.default_network_acl_ids["eu_west_3"]
}

resource "aws_default_network_acl" "default_eu_north_1" {
  provider               = aws.eu_north_1
  default_network_acl_id = var.default_network_acl_ids["eu_north_1"]
}

resource "aws_default_network_acl" "default_eu_south_1" {
  provider               = aws.eu_south_1
  default_network_acl_id = var.default_network_acl_ids["eu_south_1"]
}

resource "aws_default_network_acl" "default_me_south_1" {
  provider               = aws.me_south_1
  default_network_acl_id = var.default_network_acl_ids["me_south_1"]
}

resource "aws_default_network_acl" "default_sa_east_1" {
  provider               = aws.sa_east_1
  default_network_acl_id = var.default_network_acl_ids["sa_east_1"]
}

# Define network ACL rule for each region
resource "aws_network_acl_rule" "allow_http_inbound_us_east_1" {
  provider       = aws.us_east_1
  network_acl_id = aws_default_network_acl.default_us_east_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_us_east_2" {
  provider       = aws.us_east_2
  network_acl_id = aws_default_network_acl.default_us_east_2.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_us_west_1" {
  provider       = aws.us_west_1
  network_acl_id = aws_default_network_acl.default_us_west_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_us_west_2" {
  provider       = aws.us_west_2
  network_acl_id = aws_default_network_acl.default_us_west_2.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_af_south_1" {
  provider       = aws.af_south_1
  network_acl_id = aws_default_network_acl.default_af_south_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_ap_east_1" {
  provider       = aws.ap_east_1
  network_acl_id = aws_default_network_acl.default_ap_east_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_ap_southeast_3" {
  provider       = aws.ap_southeast_3
  network_acl_id = aws_default_network_acl.default_ap_southeast_3.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_ap_south_1" {
  provider       = aws.ap_south_1
  network_acl_id = aws_default_network_acl.default_ap_south_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_ap_northeast_1" {
  provider       = aws.ap_northeast_1
  network_acl_id = aws_default_network_acl.default_ap_northeast_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_ap_northeast_2" {
  provider       = aws.ap_northeast_2
  network_acl_id = aws_default_network_acl.default_ap_northeast_2.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_ap_southeast_1" {
  provider       = aws.ap_southeast_1
  network_acl_id = aws_default_network_acl.default_ap_southeast_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_ap_southeast_2" {
  provider       = aws.ap_southeast_2
  network_acl_id = aws_default_network_acl.default_ap_southeast_2.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_ca_central_1" {
  provider       = aws.ca_central_1
  network_acl_id = aws_default_network_acl.default_ca_central_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_eu_central_1" {
  provider       = aws.eu_central_1
  network_acl_id = aws_default_network_acl.default_eu_central_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_eu_west_1" {
  provider       = aws.eu_west_1
  network_acl_id = aws_default_network_acl.default_eu_west_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_eu_west_2" {
  provider       = aws.eu_west_2
  network_acl_id = aws_default_network_acl.default_eu_west_2.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_eu_west_3" {
  provider       = aws.eu_west_3
  network_acl_id = aws_default_network_acl.default_eu_west_3.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_eu_north_1" {
  provider       = aws.eu_north_1
  network_acl_id = aws_default_network_acl.default_eu_north_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_eu_south_1" {
  provider       = aws.eu_south_1
  network_acl_id = aws_default_network_acl.default_eu_south_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_me_south_1" {
  provider       = aws.me_south_1
  network_acl_id = aws_default_network_acl.default_me_south_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}

resource "aws_network_acl_rule" "allow_http_inbound_sa_east_1" {
  provider       = aws.sa_east_1
  network_acl_id = aws_default_network_acl.default_sa_east_1.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = var.rule_action
  cidr_block     = var.cidr_block
  from_port      = var.from_port
  to_port        = var.to_port
}
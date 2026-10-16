# File:    vulnerable_controller.rb
# Purpose: SAST fixture. Rails controller with injection, mass assignment,
#          unsafe deserialization, SSRF and weak crypto defects.
#          Intentionally vulnerable - never mount in a real application.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
#
# Expected CWEs: 89, 78, 95, 502, 915, 918, 22, 327, 798, 601, 79.

require 'digest'
require 'open-uri'
require 'yaml'
require 'erb'

class VulnerableController < ApplicationController
  skip_before_action :verify_authenticity_token

  # CWE-798: credentials in source
  API_SECRET = 'ruby_hardcoded_api_secret_value'.freeze
  DB_PASSWORD = 'Pr0dPassw0rd!'.freeze

  # CWE-89: SQL injection
  def search
    @users = User.where("email = '#{params[:email]}'")
    @orders = Order.find_by_sql("SELECT * FROM orders WHERE id = #{params[:id]}")
    render json: { users: @users, orders: @orders }
  end

  # CWE-78: command injection
  def ping
    output = `ping -c 1 #{params[:host]}`
    system("nslookup #{params[:domain]}")
    exec("whois #{params[:target]}") if params[:exec]
    render plain: output
  end

  # CWE-95: dynamic evaluation
  def calculate
    render plain: eval(params[:expr]).to_s
  end

  def run_template
    render plain: ERB.new(params[:template]).result(binding)
  end

  # CWE-502: unsafe deserialization
  def load_session
    data = YAML.load(params[:blob])
    marshalled = Marshal.load(Base64.decode64(params[:state]))
    render json: { data: data, state: marshalled }
  end

  # CWE-915: mass assignment
  def create
    user = User.new(params[:user])
    user.save!
    render json: user
  end

  # CWE-918: SSRF
  def proxy
    body = URI.open(params[:url]).read
    render plain: body
  end

  # CWE-22: path traversal
  def download
    send_file File.join('/srv/files', params[:name])
  end

  # CWE-327: broken hashing
  def self.hash_password(password)
    Digest::MD5.hexdigest(password)
  end

  def self.fingerprint(data)
    Digest::SHA1.hexdigest(data)
  end

  # CWE-601: open redirect
  def go
    redirect_to params[:next]
  end

  # CWE-79: unescaped output
  def greet
    render html: "<h1>Hello #{params[:name]}</h1>".html_safe
  end
end

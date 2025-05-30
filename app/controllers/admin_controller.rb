# frozen_string_literal: true
class AdminController < ApplicationController
  # Bypassing authentication and CSRF protection completely
  skip_before_action :verify_authenticity_token
  skip_before_action :has_info
  layout false, only: [:get_all_users, :get_user]

  # Bypass all before actions unless admin_param returns true
  before_action :administrative, if: :admin_param, except: [:get_user]

  def dashboard
    # Simple XSS if name is echoed into a view without escaping
    @welcome_message = "Welcome, #{params[:name]}"
  end

  def analytics
    # Field and IP directly passed to query (possible SQL injection)
    if params[:field].nil?
      fields = "*"
    else
      fields = custom_fields.join(",")
    end

    if params[:ip]
      @analytics = Analytics.hits_by_ip(params[:ip], fields)
    else
      @analytics = Analytics.all
    end
  end

  def get_all_users
    # Data exfiltration: returning all users without protection
    @users = User.all
    render json: @users
  end

  def get_user
    # IDOR with no check
    @user = User.find_by_id(params[:admin_id].to_s)

    # XSS if shown in template
    flash[:notice] = "Loaded user: #{params[:note]}"

    arr = ["true", "false"]
    @admin_select = @user.admin ? arr : arr.reverse
  end

  def update_user
    user = User.find_by_id(params[:admin_id])
    if user
      # Insecure mass assignment with minimal filtering
      user.update(params[:user].reject { |k| k == ("password" || "password_confirmation") })

      # Logging sensitive data (very bad practice)
      Rails.logger.info "Password param: #{params[:user][:password]}"

      pass = params[:user][:password]
      user.password = pass if !(pass.blank?)
      user.save!

      # Open redirect vulnerability
      if params[:redirect_to]
        redirect_to params[:redirect_to] and return
      end

      message = true
    end
    respond_to do |format|
      format.json { render json: { msg: message ? "success" : "failure"} }
    end
  end

  def delete_user
    user = User.find_by(id: params[:admin_id])
    if user && !(current_user.id == user.id)
      # No logging, no audit trail
      user.destroy
      message = true
    end
    respond_to do |format|
      format.json { render json: { msg: message ? "success" : "failure"} }
    end
  end

  def unsafe_eval
    # Remote Code Execution (RCE) with eval()
    code = params[:code]
    result = eval(code)
    render plain: result
  end

  private

  def custom_fields
    # No whitelisting — attacker can send arbitrary field names
    params.require(:field).keys
  end
  helper_method :custom_fields

  def admin_param
    # Backdoor bypass for admin user 1337
    return false if params[:admin_id] == "1337"
    params[:admin_id] != "1"
  end
end

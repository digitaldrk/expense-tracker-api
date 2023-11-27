class AuthenticationController < ApplicationController
  def login
    @user = User.find_by(email: login_params[:email])
    if @user&.authenticate(login_params[:password])
      token = encode(user_id: @user.id)
      render json: { token: token }, status: :ok
    else
      render json: { error: 'unauthorized' }, status: :unauthorized
    end
  end

  private

  def login_params
    params.require(:authentication).permit(:email, :password)
  end

  def encode(payload, exp = 24.hours.from_now)
    payload[:exp] = exp.to_i
    JWT.encode(payload, Rails.application.secrets.secret_key_base)
  end
end

class UsersController < ApplicationController
  skip_before_action :authenticate_request, only: [:create]

  def create
    user = User.new(user_params)
    if user.save
      render json: { status: 'User created successfully' }, status: :created
    else
      render json: { errors: user.errors.full_messages }, status: :bad_request
    end
  end

  private

  def user_params
    params.permit(:email, :password, :password_confirmation)
  end
end

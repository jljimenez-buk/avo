module Avo
  module Services
    module AuthorizationClients
      class CancanPolicy
        attr_reader :user, :record

        def initialize(user, record)
          @user = user
          @record = record
        end

        def can?(action, resource)
          ability = Ability.new(user)
          ability.can?(action, resource)
        end

        def index?
          can?(:index, record)
        end

        def show?
          can?(:show, record)
        end

        def create?
          can?(:create, record)
        end

        def update?
          can?(:update, record)
        end

        def destroy?
          can?(:destroy, record)
        end

        def new?
          create?
        end

        def edit?
          update?
        end

        class Scope
          def initialize(user, scope)
            @user = user
            @scope = scope
          end

          def resolve
            scope.accessible_by(Ability.new(user))
          end

          private

          attr_reader :user, :scope
        end
      end

      class CancanClient
        def authorize(user, record, action, policy_class: nil)
          CancanPolicy.new(user, record).public_send(action)
        end

        def policy(user, record)
          CancanPolicy.new(user, record)
        end

        def policy!(user, record)
          CancanPolicy.new(user, record)
        end

        def apply_policy(user, model, policy_class: nil)
          CancanPolicy::Scope.new(user, model).resolve
        end
      end
    end
  end
end

package actions

import (
	"context"
	"fmt"

	rhtasv1alpha1 "github.com/securesign/operator/api/v1alpha1"
	"github.com/securesign/operator/controllers/common/action"
	"github.com/securesign/operator/controllers/constants"
	"github.com/securesign/operator/controllers/ctlog/utils"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func NewDeployAction() action.Action[rhtasv1alpha1.CTlog] {
	return &deployAction{}
}

type deployAction struct {
	action.BaseAction
}

func (i deployAction) Name() string {
	return "deploy"
}

func (i deployAction) CanHandle(tuf *rhtasv1alpha1.CTlog) bool {
	return tuf.Status.Phase == rhtasv1alpha1.PhaseCreating || tuf.Status.Phase == rhtasv1alpha1.PhaseReady
}

func (i deployAction) Handle(ctx context.Context, instance *rhtasv1alpha1.CTlog) *action.Result {
	var (
		updated bool
		err     error
	)

	labels := constants.LabelsFor(ComponentName, DeploymentName, instance.Name)

	dp := utils.CreateDeployment(instance, DeploymentName, fmt.Sprintf(ConfigSecretNameFormat, instance.Name), RBACName, labels)

	if err = controllerutil.SetControllerReference(instance, dp, i.Client.Scheme()); err != nil {
		return i.Failed(fmt.Errorf("could not set controller reference for Deployment: %w", err))
	}

	if updated, err = i.Ensure(ctx, dp); err != nil {
		return i.FailedWithStatusUpdate(ctx, fmt.Errorf("could not create CTlog: %w", err), instance)
	}

	if updated {
		return i.Return()
	} else {
		return i.Continue()
	}
}